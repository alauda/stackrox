package m194tom195

import (
	"github.com/stackrox/rox/migrator/types"
	"github.com/stackrox/rox/pkg/logging"
)

var (
	batchSize = 2000
	log       = logging.LoggerForModule()
)

func migrate(database *types.Databases) error {
	//ctx := sac.WithAllAccess(context.Background())
	//pgutils.CreateTableFromModel(ctx, database.GormDB, schema.CreateTableVulnerabilityRequestsStmt)
	//
	//return updateGlobalScope(ctx, database)

	// This migration has been reverted due to the feature being disabled by default.
	// We can't easily revert due to the way migrations stack on top of each other.
	return nil
}

//func updateGlobalScope(ctx context.Context, database *types.Databases) error {
//	db := database.GormDB.WithContext(ctx).Table(schema.VulnerabilityRequestsTableName)
//	query := database.GormDB.WithContext(ctx).Table(schema.VulnerabilityRequestsTableName).Select("serialized")
//	rows, err := query.Rows()
//	if err != nil {
//		return errors.Wrapf(err, "failed to query table %s", schema.VulnerabilityRequestsTableName)
//	}
//	defer func() { _ = rows.Close() }()
//
//	var convertedObjs []*schema.VulnerabilityRequests
//	var count int
//	for rows.Next() {
//		var obj schema.VulnerabilityRequests
//		if err = query.ScanRows(rows, &obj); err != nil {
//			return errors.Wrap(err, "failed to scan vulnerability_requests table rows")
//		}
//		proto, err := schema.ConvertVulnerabilityRequestToProto(&obj)
//		if err != nil {
//			return errors.Wrapf(err, "failed to convert %+v to proto", obj)
//		}
//
//		// Update the representation of global scope per the new way.
//		if proto.GetScope().GetGlobalScope() == nil {
//			continue
//		}
//		proto.Scope = &storage.VulnerabilityRequest_Scope{
//			Info: &storage.VulnerabilityRequest_Scope_ImageScope{
//				ImageScope: &storage.VulnerabilityRequest_Scope_Image{
//					Registry: ".*",
//					Remote:   ".*",
//					Tag:      ".*",
//				},
//			},
//		}
//
//		converted, err := schema.ConvertVulnerabilityRequestFromProto(proto)
//		if err != nil {
//			return errors.Wrapf(err, "failed to convert from proto %+v", proto)
//		}
//		convertedObjs = append(convertedObjs, converted)
//		count++
//
//		if len(convertedObjs) == batchSize {
//			if err = db.
//				Clauses(clause.OnConflict{UpdateAll: true}).
//				Model(schema.CreateTableVulnerabilityRequestsStmt.GormModel).
//				Create(&convertedObjs).Error; err != nil {
//				return errors.Wrapf(err, "failed to upsert converted %d objects after %d upserted", len(convertedObjs), count-len(convertedObjs))
//			}
//			convertedObjs = convertedObjs[:0]
//		}
//	}
//	if rows.Err() != nil {
//		return errors.Wrapf(rows.Err(), "failed to get rows for %s", schema.VulnerabilityRequestsTableName)
//	}
//
//	if len(convertedObjs) > 0 {
//		if err = db.
//			Clauses(clause.OnConflict{UpdateAll: true}).
//			Model(schema.CreateTableVulnerabilityRequestsStmt.GormModel).
//			Create(&convertedObjs).Error; err != nil {
//			return errors.Wrapf(err, "failed to upsert last %d objects", len(convertedObjs))
//		}
//	}
//	log.Infof("Updated %d global scope vulnerability exceptions", count)
//	return nil
//}
