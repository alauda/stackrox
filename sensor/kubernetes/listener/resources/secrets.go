package resources

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/cloudflare/cfssl/certinfo"
	"github.com/stackrox/rox/generated/internalapi/central"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/docker/types"
	"github.com/stackrox/rox/pkg/features"
	"github.com/stackrox/rox/pkg/protoconv"
	"github.com/stackrox/rox/pkg/registries/docker"
	"github.com/stackrox/rox/pkg/registries/rhel"
	"github.com/stackrox/rox/pkg/urlfmt"
	"github.com/stackrox/rox/pkg/utils"
	"github.com/stackrox/rox/pkg/uuid"
	"github.com/stackrox/rox/sensor/common/registry"
	v1 "k8s.io/api/core/v1"
)

const (
	redhatRegistryEndpoint = "registry.redhat.io"

	saAnnotation = "kubernetes.io/service-account.name"
	defaultSA    = "default"
)

var dataTypeMap = map[string]storage.SecretType{
	"-----BEGIN CERTIFICATE-----":              storage.SecretType_PUBLIC_CERTIFICATE,
	"-----BEGIN NEW CERTIFICATE REQUEST-----":  storage.SecretType_CERTIFICATE_REQUEST,
	"-----BEGIN PRIVACY-ENHANCED MESSAGE-----": storage.SecretType_PRIVACY_ENHANCED_MESSAGE,
	"-----BEGIN OPENSSH PRIVATE KEY-----":      storage.SecretType_OPENSSH_PRIVATE_KEY,
	"-----BEGIN PGP PRIVATE KEY BLOCK-----":    storage.SecretType_PGP_PRIVATE_KEY,
	"-----BEGIN EC PRIVATE KEY-----":           storage.SecretType_EC_PRIVATE_KEY,
	"-----BEGIN RSA PRIVATE KEY-----":          storage.SecretType_RSA_PRIVATE_KEY,
	"-----BEGIN DSA PRIVATE KEY-----":          storage.SecretType_DSA_PRIVATE_KEY,
	"-----BEGIN PRIVATE KEY-----":              storage.SecretType_CERT_PRIVATE_KEY,
	"-----BEGIN ENCRYPTED PRIVATE KEY-----":    storage.SecretType_ENCRYPTED_PRIVATE_KEY,
}

func getSecretType(data string) storage.SecretType {
	data = strings.TrimSpace(data)
	for dataPrefix, t := range dataTypeMap {
		if strings.HasPrefix(data, dataPrefix) {
			return t
		}
	}
	return storage.SecretType_UNDETERMINED
}

func convertInterfaceSliceToStringSlice(i []interface{}) []string {
	strSlice := make([]string, 0, len(i))
	for _, v := range i {
		strSlice = append(strSlice, fmt.Sprintf("%v", v))
	}
	return strSlice
}

func convertCFSSLName(name certinfo.Name) *storage.CertName {
	return &storage.CertName{
		CommonName:       name.CommonName,
		Country:          name.Country,
		Organization:     name.Organization,
		OrganizationUnit: name.OrganizationalUnit,
		Locality:         name.Locality,
		Province:         name.Province,
		StreetAddress:    name.StreetAddress,
		PostalCode:       name.PostalCode,
		Names:            convertInterfaceSliceToStringSlice(name.Names),
	}
}

func parseCertData(data string) *storage.Cert {
	info, err := certinfo.ParseCertificatePEM([]byte(data))
	if err != nil {
		return nil
	}
	return &storage.Cert{
		Subject:   convertCFSSLName(info.Subject),
		Issuer:    convertCFSSLName(info.Issuer),
		Sans:      info.SANs,
		StartDate: protoconv.ConvertTimeToTimestampOrNil(info.NotBefore),
		EndDate:   protoconv.ConvertTimeToTimestampOrNil(info.NotAfter),
		Algorithm: info.SignatureAlgorithm,
	}
}

func populateTypeData(secret *storage.Secret, dataFiles map[string][]byte) {
	for file, rawData := range dataFiles {
		// Try to base64 decode and if it fails then try the raw value
		var secretType storage.SecretType
		var data string
		decoded, err := base64.StdEncoding.DecodeString(string(rawData))
		if err != nil {
			data = string(rawData)
		} else {
			data = string(decoded)
		}
		secretType = getSecretType(data)

		file := &storage.SecretDataFile{
			Name: file,
			Type: secretType,
		}

		switch secretType {
		case storage.SecretType_PUBLIC_CERTIFICATE:
			file.Metadata = &storage.SecretDataFile_Cert{
				Cert: parseCertData(data),
			}
		}
		secret.Files = append(secret.Files, file)
	}
	sort.Slice(secret.Files, func(i, j int) bool {
		return secret.Files[i].Name < secret.Files[j].Name
	})
}

// secretDispatcher handles secret resource events.
type secretDispatcher struct {
	regStore *registry.Store
}

// newSecretDispatcher creates and returns a new secret handler.
func newSecretDispatcher(regStore *registry.Store) *secretDispatcher {
	return &secretDispatcher{
		regStore: regStore,
	}
}

func dockerConfigToImageIntegration(registry string, dce types.DockerConfigEntry) *storage.ImageIntegration {
	registryType := docker.GenericDockerRegistryType
	if urlfmt.TrimHTTPPrefixes(registry) == redhatRegistryEndpoint {
		registryType = rhel.RedHatRegistryType
	}

	return &storage.ImageIntegration{
		Id:         uuid.NewV4().String(),
		Type:       registryType,
		Categories: []storage.ImageIntegrationCategory{storage.ImageIntegrationCategory_REGISTRY},
		IntegrationConfig: &storage.ImageIntegration_Docker{
			Docker: &storage.DockerConfig{
				Endpoint: registry,
				Username: dce.Username,
				Password: dce.Password,
			},
		},
		Autogenerated: true,
	}
}

func (s *secretDispatcher) processDockerConfigEvent(secret *v1.Secret, action central.ResourceAction) []*central.SensorEvent {
	var dockerConfig types.DockerConfig
	switch secret.Type {
	case v1.SecretTypeDockercfg:
		data, ok := secret.Data[v1.DockerConfigKey]
		if !ok {
			return nil
		}
		if err := json.Unmarshal(data, &dockerConfig); err != nil {
			log.Error(err)
			return nil
		}
	case v1.SecretTypeDockerConfigJson:
		data, ok := secret.Data[v1.DockerConfigJsonKey]
		if !ok {
			return nil
		}
		var dockerConfigJSON types.DockerConfigJSON
		if err := json.Unmarshal(data, &dockerConfigJSON); err != nil {
			log.Error(err)
			return nil
		}
		dockerConfig = dockerConfigJSON.Auths
	default:
		_ = utils.Should(errors.New("only Docker Config secrets are allowed"))
		return nil
	}

	sensorEvents := make([]*central.SensorEvent, 0, len(dockerConfig)+1)
	registries := make([]*storage.ImagePullSecret_Registry, 0, len(dockerConfig))
	// In Kubernetes, the `default` service account always exists in each namespace (it is recreated upon deletion).
	// The default service account always contains an API token.
	// In OpenShift, the default service account also contains credentials for the
	// OpenShift Container Registry, which is an internal image registry.
	fromDefaultSA := secret.GetAnnotations()[saAnnotation] == defaultSA
	for registry, dce := range dockerConfig {
		if features.LocalImageScanning.Enabled() {
			if fromDefaultSA {
				// Store the registry credentials so Sensor can reach it.
				err := s.regStore.UpsertRegistry(secret.GetNamespace(), registry, dce)
				if err != nil {
					log.Errorf("Unable to upsert registry %q into store: %v", registry, err)
				}
			}
		}
		ii := dockerConfigToImageIntegration(registry, dce)
		sensorEvents = append(sensorEvents, &central.SensorEvent{
			// Only update is supported at this time.
			Action: central.ResourceAction_UPDATE_RESOURCE,
			Resource: &central.SensorEvent_ImageIntegration{
				ImageIntegration: ii,
			},
		})

		registries = append(registries, &storage.ImagePullSecret_Registry{
			Name:     registry,
			Username: dce.Username,
		})
	}

	protoSecret := getProtoSecret(secret)
	protoSecret.Files = []*storage.SecretDataFile{{
		Name: v1.DockerConfigKey,
		Type: storage.SecretType_IMAGE_PULL_SECRET,
		Metadata: &storage.SecretDataFile_ImagePullSecret{
			ImagePullSecret: &storage.ImagePullSecret{
				Registries: registries,
			},
		},
	}}

	return append(sensorEvents, secretToSensorEvent(action, protoSecret))
}

func getProtoSecret(secret *v1.Secret) *storage.Secret {
	return &storage.Secret{
		Id:          string(secret.GetUID()),
		Name:        secret.GetName(),
		Namespace:   secret.GetNamespace(),
		Labels:      secret.GetLabels(),
		Annotations: secret.GetAnnotations(),
		CreatedAt:   protoconv.ConvertTimeToTimestamp(secret.GetCreationTimestamp().Time),
	}
}

func secretToSensorEvent(action central.ResourceAction, secret *storage.Secret) *central.SensorEvent {
	return &central.SensorEvent{
		Id:     secret.GetId(),
		Action: action,
		Resource: &central.SensorEvent_Secret{
			Secret: secret,
		},
	}
}

// ProcessEvent processes a secret resource event, and returns the sensor events to emit in response.
func (s *secretDispatcher) ProcessEvent(obj, _ interface{}, action central.ResourceAction) []*central.SensorEvent {
	secret := obj.(*v1.Secret)

	switch secret.Type {
	case v1.SecretTypeDockerConfigJson, v1.SecretTypeDockercfg:
		return s.processDockerConfigEvent(secret, action)
	case v1.SecretTypeServiceAccountToken:
		// Filter out service account tokens because we have a service account processor.
		return nil
	}

	protoSecret := getProtoSecret(secret)
	populateTypeData(protoSecret, secret.Data)
	return []*central.SensorEvent{secretToSensorEvent(action, protoSecret)}
}
