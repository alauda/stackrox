// Code generated by pg-bindings generator. DO NOT EDIT.

package schema

import (
	"fmt"
	"reflect"

	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/registry"
	"github.com/stackrox/rox/pkg/postgres/walker"
	"github.com/stackrox/rox/pkg/search"
)

var (
	// CreateTableTestParent2Stmt holds the create statement for table `test_parent2`.
	CreateTableTestParent2Stmt = &postgres.CreateStmts{
		Table: `
               create table if not exists test_parent2 (
                   Id varchar,
                   ParentId varchar,
                   Val varchar,
                   serialized bytea,
                   PRIMARY KEY(Id),
                   CONSTRAINT fk_parent_table_0 FOREIGN KEY (ParentId) REFERENCES test_grandparents(Id) ON DELETE CASCADE
               )
               `,
		GormModel: (*TestParent2)(nil),
		Indexes:   []string{},
		Children:  []*postgres.CreateStmts{},
	}

	// TestParent2Schema is the go schema for table `test_parent2`.
	TestParent2Schema = func() *walker.Schema {
		schema := registry.GetSchemaForTable("test_parent2")
		if schema != nil {
			return schema
		}
		schema = walker.Walk(reflect.TypeOf((*storage.TestParent2)(nil)), "test_parent2")
		referencedSchemas := map[string]*walker.Schema{
			"storage.TestGrandparent": TestGrandparentsSchema,
		}

		schema.ResolveReferences(func(messageTypeName string) *walker.Schema {
			return referencedSchemas[fmt.Sprintf("storage.%s", messageTypeName)]
		})
		schema.SetOptionsMap(search.Walk(v1.SearchCategory(68), "testparent2", (*storage.TestParent2)(nil)))
		registry.RegisterTable(schema, CreateTableTestParent2Stmt)
		return schema
	}()
)

const (
	TestParent2TableName = "test_parent2"
)

// TestParent2 holds the Gorm model for Postgres table `test_parent2`.
type TestParent2 struct {
	Id                  string           `gorm:"column:id;type:varchar;primaryKey"`
	ParentId            string           `gorm:"column:parentid;type:varchar"`
	Val                 string           `gorm:"column:val;type:varchar"`
	Serialized          []byte           `gorm:"column:serialized;type:bytea"`
	TestGrandparentsRef TestGrandparents `gorm:"foreignKey:parentid;references:id;belongsTo;constraint:OnDelete:CASCADE"`
}
