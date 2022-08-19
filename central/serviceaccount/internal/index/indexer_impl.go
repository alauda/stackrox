// Code generated by blevebindings generator. DO NOT EDIT.

package index

import (
	"bytes"
	bleve "github.com/blevesearch/bleve/v2"
	metrics "github.com/stackrox/rox/central/metrics"
	mappings "github.com/stackrox/rox/central/serviceaccount/mappings"
	v1 "github.com/stackrox/rox/generated/api/v1"
	storage "github.com/stackrox/rox/generated/storage"
	batcher "github.com/stackrox/rox/pkg/batcher"
	ops "github.com/stackrox/rox/pkg/metrics"
	search "github.com/stackrox/rox/pkg/search"
	blevesearch "github.com/stackrox/rox/pkg/search/blevesearch"
	"time"
)

const batchSize = 5000

const resourceName = "ServiceAccount"

type indexerImpl struct {
	index bleve.Index
}

type serviceAccountWrapper struct {
	*storage.ServiceAccount `json:"service_account"`
	Type                    string `json:"type"`
}

func (b *indexerImpl) AddServiceAccount(serviceaccount *storage.ServiceAccount) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Add, "ServiceAccount")
	if err := b.index.Index(serviceaccount.GetId(), &serviceAccountWrapper{
		ServiceAccount: serviceaccount,
		Type:           v1.SearchCategory_SERVICE_ACCOUNTS.String(),
	}); err != nil {
		return err
	}
	return nil
}

func (b *indexerImpl) AddServiceAccounts(serviceaccounts []*storage.ServiceAccount) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.AddMany, "ServiceAccount")
	batchManager := batcher.New(len(serviceaccounts), batchSize)
	for {
		start, end, ok := batchManager.Next()
		if !ok {
			break
		}
		if err := b.processBatch(serviceaccounts[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func (b *indexerImpl) processBatch(serviceaccounts []*storage.ServiceAccount) error {
	batch := b.index.NewBatch()
	for _, serviceaccount := range serviceaccounts {
		if err := batch.Index(serviceaccount.GetId(), &serviceAccountWrapper{
			ServiceAccount: serviceaccount,
			Type:           v1.SearchCategory_SERVICE_ACCOUNTS.String(),
		}); err != nil {
			return err
		}
	}
	return b.index.Batch(batch)
}

func (b *indexerImpl) Count(q *v1.Query, opts ...blevesearch.SearchOption) (int, error) {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Count, "ServiceAccount")
	return blevesearch.RunCountRequest(v1.SearchCategory_SERVICE_ACCOUNTS, q, b.index, mappings.OptionsMap, opts...)
}

func (b *indexerImpl) DeleteServiceAccount(id string) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Remove, "ServiceAccount")
	if err := b.index.Delete(id); err != nil {
		return err
	}
	return nil
}

func (b *indexerImpl) DeleteServiceAccounts(ids []string) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.RemoveMany, "ServiceAccount")
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
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Search, "ServiceAccount")
	return blevesearch.RunSearchRequest(v1.SearchCategory_SERVICE_ACCOUNTS, q, b.index, mappings.OptionsMap, opts...)
}
