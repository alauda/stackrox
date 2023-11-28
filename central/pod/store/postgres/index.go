// Code generated by pg-bindings generator. DO NOT EDIT.
package postgres

import (
	"time"

	metrics "github.com/stackrox/rox/central/metrics"
	v1 "github.com/stackrox/rox/generated/api/v1"
	ops "github.com/stackrox/rox/pkg/metrics"
	"github.com/stackrox/rox/pkg/postgres"
	search "github.com/stackrox/rox/pkg/search"
	pgSearch "github.com/stackrox/rox/pkg/search/postgres"
)

// NewIndexer returns new indexer for `storage.Pod`.
func NewIndexer(db postgres.DB) search.Searcher {
	return pgSearch.NewSearcher(db, v1.SearchCategory_PODS, metricSetIndexOperationDurationTime)
}

func metricSetIndexOperationDurationTime(t time.Time, op ops.Op) {
	metrics.SetIndexOperationDurationTime(t, op, "Pod")
}
