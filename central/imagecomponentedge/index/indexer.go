// Code generated by blevebindings generator. DO NOT EDIT.

package index

import (
	bleve "github.com/blevesearch/bleve/v2"
	v1 "github.com/stackrox/rox/generated/api/v1"
	storage "github.com/stackrox/rox/generated/storage"
	search "github.com/stackrox/rox/pkg/search"
	blevesearch "github.com/stackrox/rox/pkg/search/blevesearch"
)

type Indexer interface {
	AddImageComponentEdge(imagecomponentedge *storage.ImageComponentEdge) error
	AddImageComponentEdges(imagecomponentedges []*storage.ImageComponentEdge) error
	Count(q *v1.Query, opts ...blevesearch.SearchOption) (int, error)
	DeleteImageComponentEdge(id string) error
	DeleteImageComponentEdges(ids []string) error
	MarkInitialIndexingComplete() error
	NeedsInitialIndexing() (bool, error)
	Search(q *v1.Query, opts ...blevesearch.SearchOption) ([]search.Result, error)
}

func New(index bleve.Index) Indexer {
	return &indexerImpl{index: index}
}
