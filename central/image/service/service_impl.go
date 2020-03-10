package service

import (
	"context"
	"math"

	gogoTypes "github.com/gogo/protobuf/types"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/central/image/datastore"
	"github.com/stackrox/rox/central/role/resources"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/auth/permissions"
	"github.com/stackrox/rox/pkg/env"
	"github.com/stackrox/rox/pkg/expiringcache"
	"github.com/stackrox/rox/pkg/grpc/authz"
	"github.com/stackrox/rox/pkg/grpc/authz/idcheck"
	"github.com/stackrox/rox/pkg/grpc/authz/perrpc"
	"github.com/stackrox/rox/pkg/grpc/authz/user"
	"github.com/stackrox/rox/pkg/images/enricher"
	"github.com/stackrox/rox/pkg/images/types"
	"github.com/stackrox/rox/pkg/images/utils"
	"github.com/stackrox/rox/pkg/protoutils"
	"github.com/stackrox/rox/pkg/search"
	"github.com/stackrox/rox/pkg/search/paginated"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	maxImagesReturned = 1000
)

var (
	authorizer = perrpc.FromMap(map[authz.Authorizer][]string{
		user.With(permissions.View(resources.Image)): {
			"/v1.ImageService/GetImage",
			"/v1.ImageService/CountImages",
			"/v1.ImageService/ListImages",
		},
		idcheck.SensorsOnly(): {
			"/v1.ImageService/ScanImageInternal",
		},
		user.With(permissions.Modify(permissions.WithLegacyAuthForSAC(resources.Image, true))): {
			"/v1.ImageService/DeleteImages",
			"/v1.ImageService/ScanImage",
		},
		user.With(permissions.View(permissions.WithLegacyAuthForSAC(resources.Image, true))): {
			"/v1.ImageService/InvalidateScanAndRegistryCaches",
		},
	})

	reprocessInterval = env.ReprocessInterval.DurationSetting()
)

// serviceImpl provides APIs for alerts.
type serviceImpl struct {
	datastore datastore.DataStore

	metadataCache expiringcache.Cache
	scanCache     expiringcache.Cache

	enricher enricher.ImageEnricher
}

// RegisterServiceServer registers this service with the given gRPC Server.
func (s *serviceImpl) RegisterServiceServer(grpcServer *grpc.Server) {
	v1.RegisterImageServiceServer(grpcServer, s)
}

// RegisterServiceHandler registers this service with the given gRPC Gateway endpoint.
func (s *serviceImpl) RegisterServiceHandler(ctx context.Context, mux *runtime.ServeMux, conn *grpc.ClientConn) error {
	return v1.RegisterImageServiceHandler(ctx, mux, conn)
}

// AuthFuncOverride specifies the auth criteria for this API.
func (s *serviceImpl) AuthFuncOverride(ctx context.Context, fullMethodName string) (context.Context, error) {
	return ctx, authorizer.Authorized(ctx, fullMethodName)
}

// GetImage returns an image with given sha if it exists.
func (s *serviceImpl) GetImage(ctx context.Context, request *v1.ResourceByID) (*storage.Image, error) {
	if request.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "id must be specified")
	}
	request.Id = types.NewDigest(request.Id).Digest()

	image, exists, err := s.datastore.GetImage(ctx, request.GetId())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if !exists {
		return nil, status.Errorf(codes.NotFound, "image with id %q does not exist", request.GetId())
	}

	return image, nil
}

// CountImages counts the number of images that match the input query.
func (s *serviceImpl) CountImages(ctx context.Context, request *v1.RawQuery) (*v1.CountImagesResponse, error) {
	// Fill in Query.
	parsedQuery, err := search.ParseQuery(request.GetQuery(), search.MatchAllIfEmpty())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	images, err := s.datastore.Search(ctx, parsedQuery)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &v1.CountImagesResponse{Count: int32(len(images))}, nil
}

// ListImages retrieves all images in minimal form.
func (s *serviceImpl) ListImages(ctx context.Context, request *v1.RawQuery) (*v1.ListImagesResponse, error) {
	// Fill in Query.
	parsedQuery, err := search.ParseQuery(request.GetQuery(), search.MatchAllIfEmpty())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// Fill in pagination.
	paginated.FillPagination(parsedQuery, request.Pagination, maxImagesReturned)

	images, err := s.datastore.SearchListImages(ctx, parsedQuery)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &v1.ListImagesResponse{
		Images: images,
	}, nil
}

// InvalidateScanAndRegistryCaches invalidates the image scan caches
func (s *serviceImpl) InvalidateScanAndRegistryCaches(context.Context, *v1.Empty) (*v1.Empty, error) {
	s.metadataCache.RemoveAll()
	s.scanCache.RemoveAll()
	return &v1.Empty{}, nil
}

// ScanImage handles an image request from Sensor
func (s *serviceImpl) ScanImageInternal(ctx context.Context, request *v1.ScanImageInternalRequest) (*v1.ScanImageInternalResponse, error) {
	// if use saved image is true, then get all of the saved images and also add them to the central cache
	// Otherwise, we'll rely on the cache to get the data and when that data is invalidated by Central
	// then sensor will end up reaching out externally
	if request.GetUseSaved() && request.GetImage().GetId() != "" {
		img, exists, err := s.datastore.GetImage(ctx, request.GetImage().GetId())
		if err != nil {
			return nil, err
		}
		// If the scan exists and it is less than the reprocessing interval then return the scan. Otherwise, fetch it from the DB
		if exists && protoutils.Sub(gogoTypes.TimestampNow(), img.GetScan().GetScanTime()) < reprocessInterval {
			return &v1.ScanImageInternalResponse{
				Image: img,
			}, nil
		}
	}

	img := types.ToImage(request.GetImage())
	if _, err := s.enricher.EnrichImage(enricher.EnrichmentContext{}, img); err != nil {
		log.Errorf("error enriching image %q: %v", request.GetImage().GetName().GetFullName(), err)
		// purposefully, don't return here because we still need to save it into the DB so there is a reference
		// even if we weren't able to enrich it
	}

	// Save the image if we received an ID from sensor
	// Otherwise, our inferred ID may not match
	if img.GetId() != "" {
		if err := s.datastore.UpsertImage(ctx, img); err != nil {
			return nil, err
		}
	}

	return &v1.ScanImageInternalResponse{
		Image: img,
	}, nil
}

// ScanImage scans an image and returns the result
func (s *serviceImpl) ScanImage(ctx context.Context, request *v1.ScanImageRequest) (*storage.Image, error) {
	if request.GetImageName() == "" {
		return nil, status.Error(codes.InvalidArgument, "image name must be specified")
	}
	containerImage, err := utils.GenerateImageFromString(request.GetImageName())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	img := types.ToImage(containerImage)

	enrichmentCtx := enricher.EnrichmentContext{
		FetchOpt: enricher.IgnoreExistingImages,
	}
	if request.GetForce() {
		enrichmentCtx.FetchOpt = enricher.ForceRefetch
	}

	enrichmentResult, err := s.enricher.EnrichImage(enrichmentCtx, img)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	if !enrichmentResult.ImageUpdated || (enrichmentResult.ScanResult != enricher.ScanSucceeded) {
		return nil, status.Error(codes.Internal, "scan could not be completed. Please check that an applicable registry and scanner is integrated")
	}

	// Save the image
	img.Id = utils.GetImageID(img)
	if img.GetId() != "" {
		if err := s.datastore.UpsertImage(ctx, img); err != nil {
			return nil, err
		}
	}
	return img, nil
}

// DeleteImages deletes images based on query
func (s *serviceImpl) DeleteImages(ctx context.Context, request *v1.DeleteImagesRequest) (*v1.DeleteImagesResponse, error) {
	if request.GetQuery() == nil {
		return nil, errors.New("a scoping query is required")
	}

	query, err := search.ParseQuery(request.GetQuery().GetQuery(), search.MatchAllIfEmpty())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error parsing query: %v", err)
	}
	paginated.FillPagination(query, request.GetQuery().GetPagination(), math.MaxInt32)

	results, err := s.datastore.Search(ctx, query)
	if err != nil {
		return nil, err
	}

	response := &v1.DeleteImagesResponse{
		NumDeleted: uint32(len(results)),
		DryRun:     !request.GetConfirm(),
	}

	if !request.GetConfirm() {
		return response, nil
	}

	idSlice := search.ResultsToIDs(results)
	if err := s.datastore.DeleteImages(ctx, idSlice...); err != nil {
		return nil, err
	}
	return response, nil
}
