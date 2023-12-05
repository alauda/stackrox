package enricher

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var (
	_ driver.Enricher          = (*Enricher)(nil)
	_ driver.EnrichmentUpdater = (*Enricher)(nil)

	defaultUrl *url.URL
)

const (
	// Type is the type of data returned from the Enricher's Enrich method.
	Type = `message/vnd.clair.map.vulnerability; enricher=clair.cvss schema=https://csrc.nist.gov/schema/nvd/feed/1.1/cvss-v3.x.json`
	// DefaultFeeds is the default place to look for CVE feeds.
	//
	// The enricher expects the structure to mirror that found here: files
	// organized by year, prefixed with `nvdcve-1.1-` and with `.meta` and
	// `.json.gz` extensions.
	//
	//doc:url updater
	DefaultURL = `https://storage.googleapis.com/scanner-v4-test/nvd-bundle/nvd-data.tar.gz`

	// This appears above and must be the same.
	name = `nvd.cvss`
)

type CVE struct {
	CVE struct {
		Meta struct {
			ID string `json:"ID"`
		} `json:"CVE_data_meta"`
	} `json:"cve"`
	Impact struct {
		V3 struct {
			CVSS json.RawMessage `json:"cvssV3"`
		} `json:"baseMetricV3"`
		V2 struct {
			CVSS json.RawMessage `json:"cvssV2"`
		} `json:"baseMetricV2"`
	} `json:"impact"`
}

// Config is the configuration for Enricher.
type Config struct {
	FeedUrl *string `json:"feed_root" yaml:"feed_root"`
}

func init() {
	var err error
	defaultUrl, err = url.Parse(DefaultURL)
	if err != nil {
		panic(err)
	}
}

// Enricher provides CVSS data as enrichments to a VulnerabilityReport.
//
// Configure must be called before any other methods.
type Enricher struct {
	driver.NoopUpdater
	c   *http.Client
	url *url.URL
}

func (e Enricher) Enrich(ctx context.Context, getter driver.EnrichmentGetter, report *claircore.VulnerabilityReport) (string, []json.RawMessage, error) {
	//TODO implement me
	panic("implement me")
}

func (e Enricher) Name() string {
	return name
}

func (e Enricher) FetchEnrichment(ctx context.Context, fingerprint driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	//TODO implement me
	panic("implement me")
}

func (e Enricher) ParseEnrichment(ctx context.Context, closer io.ReadCloser) ([]driver.EnrichmentRecord, error) {
	//TODO implement me
	panic("implement me")
}

// Configure implements driver.Configurable.
func (e *Enricher) Configure(ctx context.Context, f driver.ConfigUnmarshaler, c *http.Client) error {
	var cfg Config
	e.c = c
	if err := f(&cfg); err != nil {
		return err
	}
	if cfg.FeedUrl != nil {
		if !strings.HasSuffix(*cfg.FeedUrl, "/") {
			return fmt.Errorf("URL missing trailing slash: %q", *cfg.FeedUrl)
		}
		u, err := url.Parse(*cfg.FeedUrl)
		if err != nil {
			return err
		}
		e.url = u
	} else {
		var err error
		e.url = defaultUrl
		if err != nil {
			panic("programmer error: " + err.Error())
		}
	}
	return nil
}

func (e *Enricher) downloadFile(filepath string) error {
	var err error
	for _, backoff := range []time.Duration{4, 8, 16} {
		err = e.queryURL(filepath)
		if err == nil {
			return nil // Success
		}

		time.Sleep(backoff * time.Second)
	}
	return err
}

// processDataBundle processes the JSON files in a given .tar.gz file
func processDataBundle(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()

		// End
		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		if strings.HasSuffix(header.Name, ".json") {
			var vulnerabilities struct {
				Vulnerabilities []CVE `json:"vulnerabilities"`
			}

			if err := json.NewDecoder(tr).Decode(&vulnerabilities); err != nil {
				return err
			}

			for _, v := range vulnerabilities.Vulnerabilities {
				fmt.Printf("CVE ID: %s\n", v.CVE.Meta.ID)
				fmt.Printf("CVSS v3: %s\n", string(v.Impact.V3.CVSS))
				fmt.Printf("CVSS v2: %s\n", string(v.Impact.V2.CVSS))
			}
		}
	}

	return nil
}

func (e *Enricher) queryURL(filepath string) error {
	resp, err := http.Get(e.url.Path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}
