// Code generated by pg-bindings generator. DO NOT EDIT.

package schema

import (
	"fmt"
	"reflect"

	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/postgres"
	schemaPkg "github.com/stackrox/rox/pkg/postgres/schema"
	"github.com/stackrox/rox/pkg/postgres/walker"
	"github.com/stackrox/rox/pkg/search"
	"github.com/stackrox/rox/pkg/search/postgres/mapping"
)

var (
	// CreateTableTestParent3Stmt holds the create statement for table `test_parent3`.
	CreateTableTestParent3Stmt = &postgres.CreateStmts{
		GormModel: (*TestParent3)(nil),
		Children:  []*postgres.CreateStmts{},
	}

	// TestParent3Schema is the go schema for table `test_parent3`.
	TestParent3Schema = func() *walker.Schema {
		schema := schemaPkg.GetSchemaForTable("test_parent3")
		if schema != nil {
			return schema
		}
		schema = walker.Walk(reflect.TypeOf((*storage.TestParent3)(nil)), "test_parent3")
		referencedSchemas := map[string]*walker.Schema{
			"storage.TestGrandparent": TestGrandparentsSchema,
		}

		schema.ResolveReferences(func(messageTypeName string) *walker.Schema {
			return referencedSchemas[fmt.Sprintf("storage.%s", messageTypeName)]
		})
		schema.SetOptionsMap(search.Walk(v1.SearchCategory(112), "testparent3", (*storage.TestParent3)(nil)))
		schemaPkg.RegisterTable(schema, CreateTableTestParent3Stmt)
		mapping.RegisterCategoryToTable(v1.SearchCategory(112), schema)
		return schema
	}()
)

const (
	TestParent3TableName = "test_parent3"
)

// TestParent3 holds the Gorm model for Postgres table `test_parent3`.
type TestParent3 struct {
	Id                  string           `gorm:"column:id;type:varchar;primaryKey"`
	ParentId            string           `gorm:"column:parentid;type:varchar"`
	Val                 string           `gorm:"column:val;type:varchar"`
	Serialized          []byte           `gorm:"column:serialized;type:bytea"`
	TestGrandparentsRef TestGrandparents `gorm:"foreignKey:parentid;references:id;belongsTo;constraint:OnDelete:CASCADE"`
}
