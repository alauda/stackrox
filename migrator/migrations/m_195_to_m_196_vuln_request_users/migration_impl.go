package m195tom196

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
	//pgutils.CreateTableFromModel(ctx, database.GormDB, new.CreateTableVulnerabilityRequestsStmt)
	//
	//return updateGlobalScope(ctx, database)

	// This migration has been reverted due to the feature being disabled by default.
	// We can't easily revert due to the way migrations stack on top of each other.
	return nil
}

//func updateGlobalScope(ctx context.Context, database *types.Databases) error {
//	previousStore := previous.New(database.PostgresDB)
//	updatedStore := updated.New(database.PostgresDB)
//
//	var updatedObjs []*storage.VulnerabilityRequest
//	var count int
//	err := previousStore.Walk(ctx, func(obj *storage.VulnerabilityRequest) error {
//		updated := obj.Clone()
//		if requester := obj.GetRequestor(); requester != nil {
//			updated.RequesterV2 = convertSlimUserToRequester(obj.GetRequestor())
//		}
//		if approvers := obj.GetApprovers(); len(approvers) > 0 {
//			updated.ApproversV2 = convertSlimUserToApprovers(obj.GetApprovers())
//		}
//		if obj.GetDeferralReq() != nil && obj.GetDeferralReq().GetExpiry() != nil {
//			if obj.GetDeferralReq().GetExpiry().GetExpiresWhenFixed() {
//				updated.GetDeferralReq().Expiry.ExpiryType = storage.RequestExpiry_ANY_CVE_FIXABLE
//			} else {
//				updated.GetDeferralReq().Expiry.ExpiryType = storage.RequestExpiry_TIME
//			}
//		}
//
//		updatedObjs = append(updatedObjs, updated)
//		count++
//
//		if len(updatedObjs) == batchSize {
//			err := updatedStore.UpsertMany(ctx, updatedObjs)
//			if err != nil {
//				return errors.Wrapf(err, "failed to write updated records to %s table", new.VulnerabilityRequestsTableName)
//			}
//			updatedObjs = updatedObjs[:0]
//		}
//		return nil
//	})
//
//	if err != nil {
//		return errors.Wrapf(err, "failed to update %s table", new.VulnerabilityRequestsTableName)
//	}
//
//	if len(updatedObjs) > 0 {
//		err := updatedStore.UpsertMany(ctx, updatedObjs)
//		if err != nil {
//			return errors.Wrapf(err, "failed to write updated records to %s table", new.VulnerabilityRequestsTableName)
//		}
//	}
//	log.Infof("Updated %d vulnerability exceptions", count)
//	return nil
//}
//
//func convertSlimUserToRequester(user *storage.SlimUser) *storage.Requester {
//	if user == nil {
//		return nil
//	}
//	return &storage.Requester{
//		Id:   user.GetId(),
//		Name: user.GetName(),
//	}
//}
//
//func convertSlimUserToApprovers(users []*storage.SlimUser) []*storage.Approver {
//	approvers := make([]*storage.Approver, 0, len(users))
//	for _, user := range users {
//		if user == nil {
//			continue
//		}
//		approvers = append(approvers, &storage.Approver{
//			Id:   user.GetId(),
//			Name: user.GetName(),
//		})
//	}
//	if len(approvers) == 0 {
//		return nil
//	}
//	return approvers
//}
