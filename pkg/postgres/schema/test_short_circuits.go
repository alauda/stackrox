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
	"github.com/stackrox/rox/pkg/search/postgres/mapping"
)

var (
	// CreateTableTestShortCircuitsStmt holds the create statement for table `test_short_circuits`.
	CreateTableTestShortCircuitsStmt = &postgres.CreateStmts{
		GormModel: (*TestShortCircuits)(nil),
		Children:  []*postgres.CreateStmts{},
	}

	// TestShortCircuitsSchema is the go schema for table `test_short_circuits`.
	TestShortCircuitsSchema = func() *walker.Schema {
		schema := GetSchemaForTable("test_short_circuits")
		if schema != nil {
			return schema
		}
		schema = walker.Walk(reflect.TypeOf((*storage.TestShortCircuit)(nil)), "test_short_circuits")
		referencedSchemas := map[string]*walker.Schema{
			"storage.TestChild1":        TestChild1Schema,
			"storage.TestG2GrandChild1": TestG2GrandChild1Schema,
		}

		schema.ResolveReferences(func(messageTypeName string) *walker.Schema {
			return referencedSchemas[fmt.Sprintf("storage.%s", messageTypeName)]
		})
		schema.SetOptionsMap(search.Walk(v1.SearchCategory(114), "testshortcircuit", (*storage.TestShortCircuit)(nil)))
		schema.ScopingResource = resources.Namespace
		RegisterTable(schema, CreateTableTestShortCircuitsStmt)
		mapping.RegisterCategoryToTable(v1.SearchCategory(114), schema)
		return schema
	}()
)

const (
	// TestShortCircuitsTableName specifies the name of the table in postgres.
	TestShortCircuitsTableName = "test_short_circuits"
)

// TestShortCircuits holds the Gorm model for Postgres table `test_short_circuits`.
type TestShortCircuits struct {
	ID             string `gorm:"column:id;type:varchar;primaryKey"`
	ChildID        string `gorm:"column:childid;type:varchar"`
	G2GrandchildID string `gorm:"column:g2grandchildid;type:varchar"`
	Serialized     []byte `gorm:"column:serialized;type:bytea"`
	TenantID       string `gorm:"column:tenant_id;type:varchar"`
}
