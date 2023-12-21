package harbor

import (
	"regexp"
	"strings"

	"github.com/stackrox/rox/generated/storage"
)

type Severity string

const (
	Unknown  Severity = "Unknown"
	Low      Severity = "Low"
	Medium   Severity = "Medium"
	High     Severity = "High"
	Critical Severity = "Critical"
)

var vulnNamePattern = regexp.MustCompile(`((CVE|ALAS|DSA)-\d{4}-\d+)|((RHSA|RHBA|RHEA)-\d{4}:\d+)`)

func vulnerabilities(vulnerabilities []*Vulnerability) []*storage.EmbeddedVulnerability {
	vulns := make([]*storage.EmbeddedVulnerability, 0, len(vulnerabilities))
	for _, ccVuln := range vulnerabilities {
		vuln := &storage.EmbeddedVulnerability{
			Cve:               vulnName(ccVuln.ID),
			Cvss:              ccVuln.GetCvssScore(),
			Summary:           ccVuln.Description,
			Link:              link(ccVuln.Links),
			VulnerabilityType: storage.EmbeddedVulnerability_IMAGE_VULNERABILITY,
			Severity:          normalizedSeverity(ccVuln.Severity),
			ScoreVersion:      ccVuln.GetCvssScoreVersion(),
			CvssV2:            ccVuln.GetCvssV2Vector(),
			CvssV3:            ccVuln.GetCvssV3Vector(),
		}
		if ccVuln.FixVersion != "" {
			vuln.SetFixedBy = &storage.EmbeddedVulnerability_FixedBy{
				FixedBy: ccVuln.FixVersion,
			}
		}

		vulns = append(vulns, vuln)
	}

	return vulns
}

func vulnName(original string) string {
	vulnID := vulnNamePattern.FindString(original)
	if vulnID == "" {
		return original
	}

	return vulnID
}

func link(links []string) string {
	return strings.Join(links, " ")
}

func normalizedSeverity(severity Severity) storage.VulnerabilitySeverity {
	switch severity {
	case Low:
		return storage.VulnerabilitySeverity_LOW_VULNERABILITY_SEVERITY
	case Medium:
		return storage.VulnerabilitySeverity_MODERATE_VULNERABILITY_SEVERITY
	case High:
		return storage.VulnerabilitySeverity_IMPORTANT_VULNERABILITY_SEVERITY
	case Critical:
		return storage.VulnerabilitySeverity_CRITICAL_VULNERABILITY_SEVERITY
	default:
		return storage.VulnerabilitySeverity_UNKNOWN_VULNERABILITY_SEVERITY
	}
}
