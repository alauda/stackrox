// Code generated by blevebindings generator. DO NOT EDIT.

package index

import (
	"bytes"
	bleve "github.com/blevesearch/bleve/v2"
	metrics "github.com/stackrox/rox/central/metrics"
	mappings "github.com/stackrox/rox/central/reportconfigurations/mappings"
	v1 "github.com/stackrox/rox/generated/api/v1"
	storage "github.com/stackrox/rox/generated/storage"
	batcher "github.com/stackrox/rox/pkg/batcher"
	ops "github.com/stackrox/rox/pkg/metrics"
	search "github.com/stackrox/rox/pkg/search"
	blevesearch "github.com/stackrox/rox/pkg/search/blevesearch"
	"time"
)

const batchSize = 5000

const resourceName = "ReportConfiguration"

type indexerImpl struct {
	index bleve.Index
}

type reportConfigurationWrapper struct {
	*storage.ReportConfiguration `json:"report_configuration"`
	Type                         string `json:"type"`
}

func (b *indexerImpl) AddReportConfiguration(reportconfiguration *storage.ReportConfiguration) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Add, "ReportConfiguration")
	if err := b.index.Index(reportconfiguration.GetId(), &reportConfigurationWrapper{
		ReportConfiguration: reportconfiguration,
		Type:                v1.SearchCategory_REPORT_CONFIGURATIONS.String(),
	}); err != nil {
		return err
	}
	return nil
}

func (b *indexerImpl) AddReportConfigurations(reportconfigurations []*storage.ReportConfiguration) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.AddMany, "ReportConfiguration")
	batchManager := batcher.New(len(reportconfigurations), batchSize)
	for {
		start, end, ok := batchManager.Next()
		if !ok {
			break
		}
		if err := b.processBatch(reportconfigurations[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func (b *indexerImpl) processBatch(reportconfigurations []*storage.ReportConfiguration) error {
	batch := b.index.NewBatch()
	for _, reportconfiguration := range reportconfigurations {
		if err := batch.Index(reportconfiguration.GetId(), &reportConfigurationWrapper{
			ReportConfiguration: reportconfiguration,
			Type:                v1.SearchCategory_REPORT_CONFIGURATIONS.String(),
		}); err != nil {
			return err
		}
	}
	return b.index.Batch(batch)
}

func (b *indexerImpl) Count(q *v1.Query, opts ...blevesearch.SearchOption) (int, error) {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Count, "ReportConfiguration")
	return blevesearch.RunCountRequest(v1.SearchCategory_REPORT_CONFIGURATIONS, q, b.index, mappings.OptionsMap, opts...)
}

func (b *indexerImpl) DeleteReportConfiguration(id string) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Remove, "ReportConfiguration")
	if err := b.index.Delete(id); err != nil {
		return err
	}
	return nil
}

func (b *indexerImpl) DeleteReportConfigurations(ids []string) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.RemoveMany, "ReportConfiguration")
	batch := b.index.NewBatch()
	for _, id := range ids {
		batch.Delete(id)
	}
	if err := b.index.Batch(batch); err != nil {
		return err
	}
	return nil
}

func (b *indexerImpl) MarkInitialIndexingComplete() error {
	return b.index.SetInternal([]byte(resourceName), []byte("old"))
}

func (b *indexerImpl) NeedsInitialIndexing() (bool, error) {
	data, err := b.index.GetInternal([]byte(resourceName))
	if err != nil {
		return false, err
	}
	return !bytes.Equal([]byte("old"), data), nil
}

func (b *indexerImpl) Search(q *v1.Query, opts ...blevesearch.SearchOption) ([]search.Result, error) {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Search, "ReportConfiguration")
	return blevesearch.RunSearchRequest(v1.SearchCategory_REPORT_CONFIGURATIONS, q, b.index, mappings.OptionsMap, opts...)
}
