// Code generated by pg-bindings generator. DO NOT EDIT.

package schema

import (
	"fmt"
	"reflect"

	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/walker"
	"github.com/stackrox/rox/pkg/sac/resources"
	"github.com/stackrox/rox/pkg/search"
)

var (
	// CreateTableTestChild1P4Stmt holds the create statement for table `test_child1_p4`.
	CreateTableTestChild1P4Stmt = &postgres.CreateStmts{
		GormModel: (*TestChild1P4)(nil),
		Children:  []*postgres.CreateStmts{},
	}

	// TestChild1P4Schema is the go schema for table `test_child1_p4`.
	TestChild1P4Schema = func() *walker.Schema {
		schema := walker.Walk(reflect.TypeOf((*storage.TestChild1P4)(nil)), "test_child1_p4")
		referencedSchemas := map[string]*walker.Schema{
			"storage.TestParent4": TestParent4Schema,
		}

		schema.ResolveReferences(func(messageTypeName string) *walker.Schema {
			return referencedSchemas[fmt.Sprintf("storage.%s", messageTypeName)]
		})
		schema.SetOptionsMap(search.Walk(v1.SearchCategory(74), "testchild1p4", (*storage.TestChild1P4)(nil)))
		schema.SetSearchScope([]v1.SearchCategory{
			v1.SearchCategory(74),
		}...)
		schema.ScopingResource = resources.Namespace
		return schema
	}()
)

const (
	// TestChild1P4TableName specifies the name of the table in postgres.
	TestChild1P4TableName = "test_child1_p4"
)

// TestChild1P4 holds the Gorm model for Postgres table `test_child1_p4`.
type TestChild1P4 struct {
	ID             string      `gorm:"column:id;type:varchar;primaryKey"`
	ParentID       string      `gorm:"column:parentid;type:uuid"`
	Val            string      `gorm:"column:val;type:varchar"`
	Serialized     []byte      `gorm:"column:serialized;type:bytea"`
	TenantID       string      `gorm:"column:tenant_id;type:varchar"`
	TestParent4Ref TestParent4 `gorm:"foreignKey:parentid;references:id;belongsTo;constraint:OnDelete:CASCADE"`
}
