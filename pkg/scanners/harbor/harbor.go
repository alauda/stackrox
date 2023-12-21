package harbor

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	gogoTypes "github.com/gogo/protobuf/types"
	"github.com/pkg/errors"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/errorhelpers"
	"github.com/stackrox/rox/pkg/httputil/proxy"
	imageTypes "github.com/stackrox/rox/pkg/images/types"
	imageUtils "github.com/stackrox/rox/pkg/images/utils"
	"github.com/stackrox/rox/pkg/logging"
	"github.com/stackrox/rox/pkg/retry"
	"github.com/stackrox/rox/pkg/scanners/types"
	"github.com/stackrox/rox/pkg/urlfmt"
	"github.com/stackrox/rox/pkg/utils"
)

const (
	requestTimeout        = 10 * time.Second
	maxOccurrenceResults  = 1000
	httpRequestRetryCount = 3
	typeString            = "harbor"
)

var (
	log = logging.LoggerForModule()
)

type packageAndVersion struct {
	name    string
	version string
}

func (p *packageAndVersion) getName() string {
	return fmt.Sprintf("%s-%s", p.name, p.version)
}

// Creator provides the type an scanners.Creator to add to the scanners Registry.
func Creator() (string, func(integration *storage.ImageIntegration) (types.Scanner, error)) {
	return typeString, func(integration *storage.ImageIntegration) (types.Scanner, error) {
		scan, err := newScanner(integration)
		return scan, err
	}
}

type harborScanner struct {
	types.ScanSemaphore
	// betaClient *containeranalysis.GrafeasV1Beta1Client

	name   string
	client *http.Client

	registry         string
	username         string
	password         string
	protoIntegration *storage.ImageIntegration
}

func getScanStartEndpoint(host, project, repository, reference string) string {
	return fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/scan", host, project, repository, reference)
}

func getScanStopEndpoint(host, project, repository, reference string) string {
	return fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/scan/stop", host, project, repository, reference)
}

func getArtifactEndpoint(host, project, repository, reference string) string {
	return fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s?page=1&page_size=10&with_tag=true&&with_scan_overview=true&with_signature=true", host, project, repository, reference)
}

func getVulnerabilitiyEndpoint(host, project, repository, reference string) string {
	return fmt.Sprintf("%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities", host, project, repository, reference)
}

func getPingEndpoint(host string) string {
	return fmt.Sprintf("%s/api/v2.0/ping", host)
}

func newScanner(integration *storage.ImageIntegration) (*harborScanner, error) {
	cfg := integration.GetHarbor()
	if err := validate(cfg); err != nil {
		return nil, err
	}

	url := urlfmt.FormatURL(cfg.GetEndpoint(), urlfmt.HTTPS, urlfmt.NoTrailingSlash)
	server := urlfmt.GetServerFromURL(url)

	scheme := urlfmt.GetSchemeFromURL(url)
	defaultScheme := urlfmt.HTTPS
	if scheme == "http" {
		defaultScheme = urlfmt.InsecureHTTP
	}
	endpoint := urlfmt.FormatURL(server, defaultScheme, urlfmt.NoTrailingSlash)
	log.Infof("harbor scanner endpoint: %s", endpoint)

	client := &http.Client{
		// No need to specify a context for HTTP requests, as the client specifies a request timeout.
		Timeout: requestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: cfg.GetInsecure(),
			},
			Proxy: proxy.FromConfig(),
			// The following values are taken from http.DefaultTransport as of go1.19.3.
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	scanner := &harborScanner{
		name:          integration.GetName(),
		client:        client,
		registry:      endpoint,
		username:      cfg.Username,
		password:      cfg.Password,
		ScanSemaphore: types.NewDefaultSemaphore(),
	}
	return scanner, nil
}

func validate(cfg *storage.HarborConfig) error {
	errorList := errorhelpers.NewErrorList("Harbor Validation")
	if cfg == nil {
		errorList.AddString("configuration required")
	}
	if cfg.GetEndpoint() == "" {
		errorList.AddString("endpoint must be specified")
	}
	return errorList.ToError()
}

func getProjectAndRepository(fullname string) (string, string) {
	items := strings.Split(fullname, "/")
	if len(items) > 1 {
		return items[0], url.PathEscape(strings.TrimLeft(fullname, items[0]+"/"))
	}
	return fullname, ""
}

func (s *harborScanner) stopScan(image *storage.Image) (bool, error) {
	project, repo := getProjectAndRepository(image.GetName().GetRemote())
	digest := imageTypes.NewDigest(imageUtils.GetSHA(image)).Digest()
	url := getScanStopEndpoint(s.registry, project, repo, digest)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return false, err
	}
	s.auth(req)

	var exists bool
	err = retry.WithRetry(func() error {
		resp, err := s.client.Do(req)
		if err != nil {
			return err
		}
		defer utils.IgnoreError(resp.Body.Close)

		switch resp.StatusCode {
		case http.StatusAccepted, http.StatusBadRequest:
			exists = true
			return nil
		case http.StatusNotFound:
			return nil
		default:
			return err
		}
	}, retry.Tries(httpRequestRetryCount), retry.WithExponentialBackoff(), retry.OnlyRetryableErrors())
	return exists, err
}

func (s *harborScanner) startScan(image *storage.Image) (bool, error) {
	project, repo := getProjectAndRepository(image.GetName().GetRemote())
	digest := imageTypes.NewDigest(imageUtils.GetSHA(image)).Digest()
	url := getScanStartEndpoint(s.registry, project, repo, digest)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return false, err
	}
	s.auth(req)

	var exists bool
	err = retry.WithRetry(func() error {
		resp, err := s.client.Do(req)
		if err != nil {
			return err
		}
		defer utils.IgnoreError(resp.Body.Close)

		switch resp.StatusCode {
		case http.StatusAccepted:
			exists = true
			return nil
		case http.StatusNotFound:
			return nil
		default:
			return err
		}
	}, retry.Tries(httpRequestRetryCount), retry.WithExponentialBackoff(), retry.OnlyRetryableErrors())
	return exists, err
}

func (s *harborScanner) waitScan(image *storage.Image) error {
	project, repo := getProjectAndRepository(image.GetName().GetRemote())
	digest := imageTypes.NewDigest(imageUtils.GetSHA(image)).Digest()
	url := getArtifactEndpoint(s.registry, project, repo, digest)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	s.auth(req)

	return waitUntil(func() (bool, error) {
		resp, err := s.client.Do(req)
		if err != nil {
			return false, err
		}
		defer utils.IgnoreError(resp.Body.Close)

		switch resp.StatusCode {
		case http.StatusOK:
			// The index report was created.
		default:
			return false, newUnexpectedStatusCodeError(resp.StatusCode)
		}

		var artifact Artifact
		if err := json.NewDecoder(resp.Body).Decode(&artifact); err != nil {
			return false, err
		}
		overview := artifact.ScanOverview["application/vnd.security.vulnerability.report; version=1.1"]
		if overview.ScanStatus == "Success" {
			return true, nil
		}
		return false, nil
	}, 1*time.Second, 40)
}
func (s *harborScanner) getVulnerabilityReport(image *storage.Image) (*VulnerabilityReport, error) {
	project, repo := getProjectAndRepository(image.GetName().GetRemote())
	url := getVulnerabilitiyEndpoint(s.registry, project, repo, image.GetName().GetTag())
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	s.auth(req)

	var vulnReport *VulnerabilityReport
	err = retry.WithRetry(func() error {
		resp, err := s.client.Do(req)
		if err != nil {
			return err
		}
		defer utils.IgnoreError(resp.Body.Close)

		switch resp.StatusCode {
		case http.StatusOK:
			// The index report was created.
		default:
			return newUnexpectedStatusCodeError(resp.StatusCode)
		}

		var result map[string]*VulnerabilityReport
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return err
		}
		vulnReport = result["application/vnd.security.vulnerability.report; version=1.1"]
		return nil
	}, retry.Tries(httpRequestRetryCount), retry.WithExponentialBackoff(), retry.OnlyRetryableErrors())
	return vulnReport, nil
}

func (s *harborScanner) GetScan(image *storage.Image) (*storage.ImageScan, error) {
	log.Infof("Retrieving scans for image %s", image.GetName().GetFullName())

	exists, err := s.stopScan(image)
	if err != nil {
		return nil, errors.Wrapf(err, "Harbor: stop scan image for %s", image.GetName().GetFullName())
	}
	if !exists {
		return nil, fmt.Errorf("Harbor: not found image for %s", image.GetName().GetFullName())
	}

	_, err = s.startScan(image)
	if err != nil {
		return nil, errors.Wrapf(err, "Harbor: start scan image for %s", image.GetName().GetFullName())
	}

	if err := s.waitScan(image); err != nil {
		return nil, errors.Wrapf(err, "Harbor: waiting scan image for %s", image.GetName().GetFullName())
	}

	report, err := s.getVulnerabilityReport(image)
	if err != nil {
		return nil, errors.Wrapf(err, "Harbor: getting vulnerability report for %s", image.GetName().GetFullName())
	}
	return imageScan(report), nil
}

func (s *harborScanner) Match(image *storage.ImageName) bool {
	return strings.Contains(s.registry, image.GetRegistry())
}

func (s *harborScanner) Test() error {
	return nil
}

func (s *harborScanner) Type() string {
	return typeString
}

func (s *harborScanner) Name() string {
	return s.protoIntegration.GetName()
}

func (s *harborScanner) GetVulnDefinitionsInfo() (*v1.VulnDefinitionsInfo, error) {
	return nil, nil
}

func waitUntil(condition func() (bool, error), interval time.Duration, maxRetries int) error {
	for i := 0; i < maxRetries; i++ {
		ok, err := condition()
		if err != nil {
			return err
		}

		if ok {
			return nil
		}

		time.Sleep(interval)
	}

	return fmt.Errorf("failed to wait")
}

// imageScan converts the given report to an image scan.
func imageScan(report *VulnerabilityReport) *storage.ImageScan {
	scan := &storage.ImageScan{
		ScanTime:        gogoTypes.TimestampNow(),
		Components:      components(report),
		OperatingSystem: "unknown",
		Notes: []storage.ImageScan_Note{
			storage.ImageScan_OS_UNAVAILABLE,
		},
	}
	return scan
}

func components(report *VulnerabilityReport) []*storage.EmbeddedImageScanComponent {
	packageVulnerabilities := make(map[packageAndVersion][]*Vulnerability)
	for _, vuln := range report.Vulnerabilities {
		pv := packageAndVersion{
			name:    vuln.Package,
			version: vuln.Version,
		}
		if _, ok := packageVulnerabilities[pv]; !ok {
			packageVulnerabilities[pv] = make([]*Vulnerability, 0)
		}
		packageVulnerabilities[pv] = append(packageVulnerabilities[pv], vuln)
	}

	components := make([]*storage.EmbeddedImageScanComponent, 0, len(packageVulnerabilities))
	for pv, vulns := range packageVulnerabilities {
		component := &storage.EmbeddedImageScanComponent{
			Name:    pv.name,
			Version: pv.version,
			Vulns:   vulnerabilities(vulns),
		}

		components = append(components, component)
	}

	return components
}
