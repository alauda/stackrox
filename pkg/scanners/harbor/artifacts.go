package harbor

type Artifact struct {
	ID                int64                   `json:"id"`
	AdditionLinks     AdditionLinks           `json:"addition_links"`
	ManifestMediaType string                  `json:"manifest_media_type"`
	MediaType         string                  `json:"media_type"`
	ProjectId         int64                   `json:"project_id"`
	RepositoryId      int64                   `json:"repository_id"`
	PullTime          string                  `json:"pull_time"`
	PushTime          string                  `json:"push_time"`
	Digest            string                  `json:"digest"`
	ScanOverview      map[string]ScanOverview `json:"scan_overview"`
	Type              string                  `json:"type"`
	Tags              []Tag                   `json:"tags"`
}

type AdditionLinks struct {
	BuildHistory    AdditionLink `json:"build_history"`
	Vulnerabilities AdditionLink `json:"vulnerabilities"`
}

type AdditionLink struct {
	Absolute bool   `json:"absolute"`
	Href     string `json:"href"`
}

type ScanOverview struct {
	ReportID   string `json:"report_id"`
	ScanStatus string `json:"scan_status"`
	StartTime  string `json:"start_time"`
	EndTime    string `json:"end_time"`
}

type Tag struct {
	ArtifactID   int64  `json:"artifact_id"`
	ID           int64  `json:"id"`
	Immutable    bool   `json:"immutable"`
	Name         string `json:"name"`
	RepositoryId int64  `json:"repository_id"`
	PullTime     string `json:"pull_time"`
	PushTime     string `json:"push_time"`
	Signed       bool   `json:"signed"`
}
