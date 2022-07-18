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
	// CreateTableTestG3GrandChild1Stmt holds the create statement for table `test_g3_grand_child1`.
	CreateTableTestG3GrandChild1Stmt = &postgres.CreateStmts{
		Table: `
               create table if not exists test_g3_grand_child1 (
                   Id varchar,
                   Val varchar,
                   serialized bytea,
                   PRIMARY KEY(Id)
               )
               `,
		GormModel: (*TestG3GrandChild1)(nil),
		Indexes:   []string{},
		Children:  []*postgres.CreateStmts{},
	}

	// TestG3GrandChild1Schema is the go schema for table `test_g3_grand_child1`.
	TestG3GrandChild1Schema = func() *walker.Schema {
		schema := registry.GetSchemaForTable("test_g3_grand_child1")
		if schema != nil {
			return schema
		}
		schema = walker.Walk(reflect.TypeOf((*storage.TestG3GrandChild1)(nil)), "test_g3_grand_child1")
		schema.SetOptionsMap(search.Walk(v1.SearchCategory(67), "testg3grandchild1", (*storage.TestG3GrandChild1)(nil)))
		registry.RegisterTable(schema, CreateTableTestG3GrandChild1Stmt)
		return schema
	}()
)

const (
	TestG3GrandChild1TableName = "test_g3_grand_child1"
)

// TestG3GrandChild1 holds the Gorm model for Postgres table `test_g3_grand_child1`.
type TestG3GrandChild1 struct {
	Id         string `gorm:"column:id;type:varchar;primaryKey"`
	Val        string `gorm:"column:val;type:varchar"`
	Serialized []byte `gorm:"column:serialized;type:bytea"`
}
