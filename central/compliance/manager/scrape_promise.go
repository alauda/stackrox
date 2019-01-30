package manager

import (
	"context"
	"errors"
	"time"

	"github.com/stackrox/rox/central/compliance/data"
	"github.com/stackrox/rox/central/compliance/framework"
	"github.com/stackrox/rox/central/scrape"
	"github.com/stackrox/rox/generated/internalapi/compliance"
	"github.com/stackrox/rox/pkg/concurrency"
)

// scrapePromise allows access to compliance data in an asynchronous way, allowing multiple runs to wait on the same
// scrape process.
type scrapePromise struct {
	domain          framework.ComplianceDomain
	dataRepoFactory data.RepositoryFactory

	finishedSig concurrency.ErrorSignal

	result framework.ComplianceDataRepository
}

// createAndRunScrape creates and returns a scrapePromise for the given domain. The returned promise will be running.
func createAndRunScrape(scrapeFactory scrape.Factory, dataRepoFactory data.RepositoryFactory, domain framework.ComplianceDomain, timeout time.Duration) *scrapePromise {
	promise := &scrapePromise{
		domain:          domain,
		finishedSig:     concurrency.NewErrorSignal(),
		dataRepoFactory: dataRepoFactory,
	}
	go promise.run(scrapeFactory, domain, timeout)
	return promise
}

func (p *scrapePromise) finish(scrapeResult map[string]*compliance.ComplianceReturn, err error) {
	if err != nil {
		p.finishedSig.SignalWithError(err)
		return
	}

	p.result, err = p.dataRepoFactory.CreateDataRepository(p.domain, scrapeResult)
	p.finishedSig.SignalWithError(err)
}

func (p *scrapePromise) WaitForResult(cancel concurrency.Waitable) (framework.ComplianceDataRepository, error) {
	err, done := p.finishedSig.WaitUntil(cancel)
	if !done {
		return nil, errors.New("cancelled while waiting for compliance results")
	}
	if err != nil {
		return nil, err
	}
	return p.result, nil
}

func (p *scrapePromise) run(scrapeFactory scrape.Factory, domain framework.ComplianceDomain, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	p.finish(scrapeFactory.RunScrape(domain, ctx))
}
