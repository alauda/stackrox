// Code generated by blevebindings generator. DO NOT EDIT.

package index

import (
	"bytes"
	bleve "github.com/blevesearch/bleve/v2"
	mappings "github.com/stackrox/rox/central/imagecveedge/mappings"
	metrics "github.com/stackrox/rox/central/metrics"
	v1 "github.com/stackrox/rox/generated/api/v1"
	storage "github.com/stackrox/rox/generated/storage"
	batcher "github.com/stackrox/rox/pkg/batcher"
	ops "github.com/stackrox/rox/pkg/metrics"
	search "github.com/stackrox/rox/pkg/search"
	blevesearch "github.com/stackrox/rox/pkg/search/blevesearch"
	"time"
)

const batchSize = 5000

const resourceName = "ImageCVEEdge"

type indexerImpl struct {
	index bleve.Index
}

type imageCVEEdgeWrapper struct {
	*storage.ImageCVEEdge `json:"image_c_v_e_edge"`
	Type                  string `json:"type"`
}

func (b *indexerImpl) AddImageCVEEdge(imagecveedge *storage.ImageCVEEdge) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Add, "ImageCVEEdge")
	if err := b.index.Index(imagecveedge.GetId(), &imageCVEEdgeWrapper{
		ImageCVEEdge: imagecveedge,
		Type:         v1.SearchCategory_IMAGE_VULN_EDGE.String(),
	}); err != nil {
		return err
	}
	return nil
}

func (b *indexerImpl) AddImageCVEEdges(imagecveedges []*storage.ImageCVEEdge) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.AddMany, "ImageCVEEdge")
	batchManager := batcher.New(len(imagecveedges), batchSize)
	for {
		start, end, ok := batchManager.Next()
		if !ok {
			break
		}
		if err := b.processBatch(imagecveedges[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func (b *indexerImpl) processBatch(imagecveedges []*storage.ImageCVEEdge) error {
	batch := b.index.NewBatch()
	for _, imagecveedge := range imagecveedges {
		if err := batch.Index(imagecveedge.GetId(), &imageCVEEdgeWrapper{
			ImageCVEEdge: imagecveedge,
			Type:         v1.SearchCategory_IMAGE_VULN_EDGE.String(),
		}); err != nil {
			return err
		}
	}
	return b.index.Batch(batch)
}

func (b *indexerImpl) Count(q *v1.Query, opts ...blevesearch.SearchOption) (int, error) {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Count, "ImageCVEEdge")
	return blevesearch.RunCountRequest(v1.SearchCategory_IMAGE_VULN_EDGE, q, b.index, mappings.OptionsMap, opts...)
}

func (b *indexerImpl) DeleteImageCVEEdge(id string) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Remove, "ImageCVEEdge")
	if err := b.index.Delete(id); err != nil {
		return err
	}
	return nil
}

func (b *indexerImpl) DeleteImageCVEEdges(ids []string) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.RemoveMany, "ImageCVEEdge")
	batch := b.index.NewBatch()
	for _, id := range ids {
		batch.Delete(id)
	}
	if err := b.index.Batch(batch); err != nil {
		return err
	}
	return nil
}

func (b *indexerImpl) MarkInitialIndexingComplete() error {
	return b.index.SetInternal([]byte(resourceName), []byte("old"))
}

func (b *indexerImpl) NeedsInitialIndexing() (bool, error) {
	data, err := b.index.GetInternal([]byte(resourceName))
	if err != nil {
		return false, err
	}
	return !bytes.Equal([]byte("old"), data), nil
}

func (b *indexerImpl) Search(q *v1.Query, opts ...blevesearch.SearchOption) ([]search.Result, error) {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Search, "ImageCVEEdge")
	return blevesearch.RunSearchRequest(v1.SearchCategory_IMAGE_VULN_EDGE, q, b.index, mappings.OptionsMap, opts...)
}
