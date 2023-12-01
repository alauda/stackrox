// Code generated by pg-bindings generator. DO NOT EDIT.

package schema

import (
	"fmt"
	"reflect"

	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/features"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/walker"
	"github.com/stackrox/rox/pkg/sac/resources"
	"github.com/stackrox/rox/pkg/search"
	"github.com/stackrox/rox/pkg/search/postgres/mapping"
)

var (
	// CreateTableComplianceOperatorProfileClusterEdgesStmt holds the create statement for table `compliance_operator_profile_cluster_edges`.
	CreateTableComplianceOperatorProfileClusterEdgesStmt = &postgres.CreateStmts{
		GormModel: (*ComplianceOperatorProfileClusterEdges)(nil),
		Children:  []*postgres.CreateStmts{},
	}

	// ComplianceOperatorProfileClusterEdgesSchema is the go schema for table `compliance_operator_profile_cluster_edges`.
	ComplianceOperatorProfileClusterEdgesSchema = func() *walker.Schema {
		schema := GetSchemaForTable("compliance_operator_profile_cluster_edges")
		if schema != nil {
			return schema
		}
		schema = walker.Walk(reflect.TypeOf((*storage.ComplianceOperatorProfileClusterEdge)(nil)), "compliance_operator_profile_cluster_edges")
		referencedSchemas := map[string]*walker.Schema{
			"storage.ComplianceOperatorProfileV2": ComplianceOperatorProfileV2Schema,
			"storage.Cluster":                     ClustersSchema,
		}

		schema.ResolveReferences(func(messageTypeName string) *walker.Schema {
			return referencedSchemas[fmt.Sprintf("storage.%s", messageTypeName)]
		})
		schema.SetOptionsMap(search.Walk(v1.SearchCategory_COMPLIANCE_PROFILE_CLUSTER_EDGE, "complianceoperatorprofileclusteredge", (*storage.ComplianceOperatorProfileClusterEdge)(nil)))
		schema.ScopingResource = resources.ComplianceOperator
		RegisterTable(schema, CreateTableComplianceOperatorProfileClusterEdgesStmt, features.ComplianceEnhancements.Enabled)
		mapping.RegisterCategoryToTable(v1.SearchCategory_COMPLIANCE_PROFILE_CLUSTER_EDGE, schema)
		return schema
	}()
)

const (
	// ComplianceOperatorProfileClusterEdgesTableName specifies the name of the table in postgres.
	ComplianceOperatorProfileClusterEdgesTableName = "compliance_operator_profile_cluster_edges"
)

// ComplianceOperatorProfileClusterEdges holds the Gorm model for Postgres table `compliance_operator_profile_cluster_edges`.
type ComplianceOperatorProfileClusterEdges struct {
	ID                             string                      `gorm:"column:id;type:varchar;primaryKey"`
	ProfileID                      string                      `gorm:"column:profileid;type:varchar"`
	ProfileUID                     string                      `gorm:"column:profileuid;type:varchar"`
	ClusterID                      string                      `gorm:"column:clusterid;type:uuid;index:complianceoperatorprofileclusteredges_sac_filter,type:btree"`
	Serialized                     []byte                      `gorm:"column:serialized;type:bytea"`
	ComplianceOperatorProfileV2Ref ComplianceOperatorProfileV2 `gorm:"foreignKey:profileid;references:id;belongsTo;constraint:OnDelete:CASCADE"`
}
