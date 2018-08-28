package search

// The following strings are the internal representation to their option value
const (
	Cluster   = "Cluster"
	ClusterID = "Cluster Id"
	Namespace = "Namespace"
	Label     = "Label"

	PolicyID    = "Policy Id"
	Enforcement = "Enforcement"
	PolicyName  = "Policy"
	Description = "Description"
	Category    = "Category"
	Severity    = "Severity"

	CVE                          = "CVE"
	CVSS                         = "CVSS"
	Component                    = "Component"
	DockerfileInstructionKeyword = "Dockerfile Instruction Keyword"
	DockerfileInstructionValue   = "Dockerfile Instruction Value"
	ImageCreatedTime             = "Image Created Time"
	ImageName                    = "Image"
	ImageSHA                     = "Image Sha"
	ImageRegistry                = "Image Registry"
	ImageRemote                  = "Image Remote"
	ImageScanTime                = "Image Scan Time"
	ImageTag                     = "Image Tag"

	CPUCoresLimit     = "CPU Cores Limit"
	CPUCoresRequest   = "CPU Cores Request"
	DeploymentID      = "Deployment Id"
	DeploymentName    = "Deployment"
	DeploymentType    = "Deployment Type"
	AddCapabilities   = "Add Capabilities"
	DropCapabilities  = "Drop Capabilities"
	EnvironmentKey    = "Environment Key"
	EnvironmentValue  = "Environment Value"
	ImagePullSecret   = "Image Pull Secret"
	MemoryLimit       = "Memory Limit (MB)"
	MemoryRequest     = "Memory Request (MB)"
	Privileged        = "Privileged"
	SecretName        = "Secret Name"
	SecretPath        = "Secret Path"
	ServiceAccount    = "Service Account"
	VolumeName        = "Volume Name"
	VolumeSource      = "Volume Source"
	VolumeDestination = "Volume Destination"
	VolumeReadonly    = "Volume ReadOnly"
	VolumeType        = "Volume Type"

	Violation = "Violation"
	Stale     = "Stale"
)
