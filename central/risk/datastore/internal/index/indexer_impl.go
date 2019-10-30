// Code generated by blevebindings generator. DO NOT EDIT.

package index

import (
	metrics "github.com/stackrox/rox/central/metrics"
	mappings "github.com/stackrox/rox/central/risk/mappings"
	v1 "github.com/stackrox/rox/generated/api/v1"
	storage "github.com/stackrox/rox/generated/storage"
	batcher "github.com/stackrox/rox/pkg/batcher"
	blevehelper "github.com/stackrox/rox/pkg/blevehelper"
	ops "github.com/stackrox/rox/pkg/metrics"
	search "github.com/stackrox/rox/pkg/search"
	blevesearch "github.com/stackrox/rox/pkg/search/blevesearch"
	"time"
)

const batchSize = 5000

const resourceName = "Risk"

type indexerImpl struct {
	index *blevehelper.BleveWrapper
}

type riskWrapper struct {
	*storage.Risk `json:"risk"`
	Type          string `json:"type"`
}

func (b *indexerImpl) AddRisk(risk *storage.Risk) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Add, "Risk")
	if err := b.index.Index.Index(risk.GetId(), &riskWrapper{
		Risk: risk,
		Type: v1.SearchCategory_RISKS.String(),
	}); err != nil {
		return err
	}
	return nil
}

func (b *indexerImpl) AddRisks(risks []*storage.Risk) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.AddMany, "Risk")
	batchManager := batcher.New(len(risks), batchSize)
	for {
		start, end, ok := batchManager.Next()
		if !ok {
			break
		}
		if err := b.processBatch(risks[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func (b *indexerImpl) processBatch(risks []*storage.Risk) error {
	batch := b.index.NewBatch()
	for _, risk := range risks {
		if err := batch.Index(risk.GetId(), &riskWrapper{
			Risk: risk,
			Type: v1.SearchCategory_RISKS.String(),
		}); err != nil {
			return err
		}
	}
	return b.index.Batch(batch)
}

func (b *indexerImpl) DeleteRisk(id string) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Remove, "Risk")
	if err := b.index.Delete(id); err != nil {
		return err
	}
	return nil
}

func (b *indexerImpl) DeleteRisks(ids []string) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.RemoveMany, "Risk")
	batch := b.index.NewBatch()
	for _, id := range ids {
		batch.Delete(id)
	}
	if err := b.index.Batch(batch); err != nil {
		return err
	}
	return nil
}

func (b *indexerImpl) ResetIndex() error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Reset, "Risk")
	return blevesearch.ResetIndex(v1.SearchCategory_RISKS, b.index.Index)
}

func (b *indexerImpl) Search(q *v1.Query, opts ...blevesearch.SearchOption) ([]search.Result, error) {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Search, "Risk")
	return blevesearch.RunSearchRequest(v1.SearchCategory_RISKS, q, b.index.Index, mappings.OptionsMap, opts...)
}
