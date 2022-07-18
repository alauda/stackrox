// Code generated by pg-bindings generator. DO NOT EDIT.

package schema

import (
	"reflect"

	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/registry"
	"github.com/stackrox/rox/pkg/postgres/walker"
	"github.com/stackrox/rox/pkg/search"
)

var (
	// CreateTableTestGGrandChild1Stmt holds the create statement for table `test_g_grand_child1`.
	CreateTableTestGGrandChild1Stmt = &postgres.CreateStmts{
		Table: `
               create table if not exists test_g_grand_child1 (
                   Id varchar,
                   Val varchar,
                   serialized bytea,
                   PRIMARY KEY(Id)
               )
               `,
		GormModel: (*TestGGrandChild1)(nil),
		Indexes:   []string{},
		Children:  []*postgres.CreateStmts{},
	}

	// TestGGrandChild1Schema is the go schema for table `test_g_grand_child1`.
	TestGGrandChild1Schema = func() *walker.Schema {
		schema := registry.GetSchemaForTable("test_g_grand_child1")
		if schema != nil {
			return schema
		}
		schema = walker.Walk(reflect.TypeOf((*storage.TestGGrandChild1)(nil)), "test_g_grand_child1")
		schema.SetOptionsMap(search.Walk(v1.SearchCategory(65), "testggrandchild1", (*storage.TestGGrandChild1)(nil)))
		registry.RegisterTable(schema, CreateTableTestGGrandChild1Stmt)
		return schema
	}()
)

const (
	TestGGrandChild1TableName = "test_g_grand_child1"
)

// TestGGrandChild1 holds the Gorm model for Postgres table `test_g_grand_child1`.
type TestGGrandChild1 struct {
	Id         string `gorm:"column:id;type:varchar;primaryKey"`
	Val        string `gorm:"column:val;type:varchar"`
	Serialized []byte `gorm:"column:serialized;type:bytea"`
}
