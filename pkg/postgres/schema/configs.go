// Code generated by pg-bindings generator. DO NOT EDIT.

package schema

import (
	"reflect"

	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/registry"
	"github.com/stackrox/rox/pkg/postgres/walker"
)

var (
	// CreateTableConfigsStmt holds the create statement for table `configs`.
	CreateTableConfigsStmt = &postgres.CreateStmts{
		Table: `
               create table if not exists configs (
                   serialized bytea
                   
               )
               `,
		GormModel: (*Configs)(nil),
		Indexes:   []string{},
		Children:  []*postgres.CreateStmts{},
	}

	// ConfigsSchema is the go schema for table `configs`.
	ConfigsSchema = func() *walker.Schema {
		schema := registry.GetSchemaForTable("configs")
		if schema != nil {
			return schema
		}
		schema = walker.Walk(reflect.TypeOf((*storage.Config)(nil)), "configs")
		registry.RegisterTable(schema, CreateTableConfigsStmt)
		return schema
	}()
)

const (
	ConfigsTableName = "configs"
)

// Configs holds the Gorm model for Postgres table `configs`.
type Configs struct {
	Serialized []byte `gorm:"column:serialized;type:bytea"`
}
