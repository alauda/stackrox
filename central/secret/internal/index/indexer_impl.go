// Code generated by blevebindings generator. DO NOT EDIT.

package index

import (
	"bytes"
	"context"
	bleve "github.com/blevesearch/bleve"
	metrics "github.com/stackrox/rox/central/metrics"
	mappings "github.com/stackrox/rox/central/secret/mappings"
	v1 "github.com/stackrox/rox/generated/api/v1"
	storage "github.com/stackrox/rox/generated/storage"
	batcher "github.com/stackrox/rox/pkg/batcher"
	ops "github.com/stackrox/rox/pkg/metrics"
	search "github.com/stackrox/rox/pkg/search"
	blevesearch "github.com/stackrox/rox/pkg/search/blevesearch"
	"time"
)

const batchSize = 5000

const resourceName = "Secret"

type indexerImpl struct {
	index bleve.Index
}

type secretWrapper struct {
	*storage.Secret `json:"secret"`
	Type            string `json:"type"`
}

func (b *indexerImpl) AddSecret(secret *storage.Secret) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Add, "Secret")
	if err := b.index.Index(secret.GetId(), &secretWrapper{
		Secret: secret,
		Type:   v1.SearchCategory_SECRETS.String(),
	}); err != nil {
		return err
	}
	return nil
}

func (b *indexerImpl) AddSecrets(secrets []*storage.Secret) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.AddMany, "Secret")
	batchManager := batcher.New(len(secrets), batchSize)
	for {
		start, end, ok := batchManager.Next()
		if !ok {
			break
		}
		if err := b.processBatch(secrets[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func (b *indexerImpl) processBatch(secrets []*storage.Secret) error {
	batch := b.index.NewBatch()
	for _, secret := range secrets {
		if err := batch.Index(secret.GetId(), &secretWrapper{
			Secret: secret,
			Type:   v1.SearchCategory_SECRETS.String(),
		}); err != nil {
			return err
		}
	}
	return b.index.Batch(batch)
}

func (b *indexerImpl) Count(ctx context.Context, q *v1.Query, opts ...blevesearch.SearchOption) (int, error) {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Count, "Secret")
	return blevesearch.RunCountRequest(v1.SearchCategory_SECRETS, q, b.index, mappings.OptionsMap, opts...)
}

func (b *indexerImpl) DeleteSecret(id string) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Remove, "Secret")
	if err := b.index.Delete(id); err != nil {
		return err
	}
	return nil
}

func (b *indexerImpl) DeleteSecrets(ids []string) error {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.RemoveMany, "Secret")
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

func (b *indexerImpl) Search(ctx context.Context, q *v1.Query, opts ...blevesearch.SearchOption) ([]search.Result, error) {
	defer metrics.SetIndexOperationDurationTime(time.Now(), ops.Search, "Secret")
	return blevesearch.RunSearchRequest(v1.SearchCategory_SECRETS, q, b.index, mappings.OptionsMap, opts...)
}