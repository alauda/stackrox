// Code generated by blevebindings generator. DO NOT EDIT.

package index

import (
	"bytes"
	bleve "github.com/blevesearch/bleve/v2"
	mappings "github.com/stackrox/rox/central/alert/mappings"
	metrics "github.com/stackrox/rox/central/metrics"
	v1 "github.com/stackrox/rox/generated/api/v1"
	storage "github.com/stackrox/rox/generated/storage"
	batcher "github.com/stackrox/rox/pkg/batcher"
	ops "github.com/stackrox/rox/pkg/metrics"
	search "github.com/stackrox/rox/pkg/search"
	blevesearch "github.com/stackrox/rox/pkg/search/blevesearch"
	"time"
)

const batchSize = 5000

const resourceName = "ListAlert"

type indexerImpl struct {
	index bleve.Index
}

type listAlertWrapper struct {
	*storage.ListAlert `json:"list_alert"`
	Type               string `json:"type"`
}

func (b *indexerImpl) AddListAlert(listalert *storage.ListAlert) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Add, "ListAlert")
	if err := b.index.Index(listalert.GetId(), &listAlertWrapper{
		ListAlert: listalert,
		Type:      v1.SearchCategory_ALERTS.String(),
	}); err != nil {
		return err
	}
	return nil
}

func (b *indexerImpl) AddListAlerts(listalerts []*storage.ListAlert) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.AddMany, "ListAlert")
	batchManager := batcher.New(len(listalerts), batchSize)
	for {
		start, end, ok := batchManager.Next()
		if !ok {
			break
		}
		if err := b.processBatch(listalerts[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func (b *indexerImpl) processBatch(listalerts []*storage.ListAlert) error {
	batch := b.index.NewBatch()
	for _, listalert := range listalerts {
		if err := batch.Index(listalert.GetId(), &listAlertWrapper{
			ListAlert: listalert,
			Type:      v1.SearchCategory_ALERTS.String(),
		}); err != nil {
			return err
		}
	}
	return b.index.Batch(batch)
}

func (b *indexerImpl) Count(q *v1.Query, opts ...blevesearch.SearchOption) (int, error) {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Count, "ListAlert")
	return blevesearch.RunCountRequest(v1.SearchCategory_ALERTS, q, b.index, mappings.OptionsMap, opts...)
}

func (b *indexerImpl) DeleteListAlert(id string) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Remove, "ListAlert")
	if err := b.index.Delete(id); err != nil {
		return err
	}
	return nil
}

func (b *indexerImpl) DeleteListAlerts(ids []string) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.RemoveMany, "ListAlert")
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
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Search, "ListAlert")
	return blevesearch.RunSearchRequest(v1.SearchCategory_ALERTS, q, b.index, mappings.OptionsMap, opts...)
}
