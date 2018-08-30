package resources

import (
	"encoding/json"
	"reflect"
	"strconv"

	ptypes "github.com/gogo/protobuf/types"
	pkgV1 "github.com/stackrox/rox/generated/api/v1"
	imageTypes "github.com/stackrox/rox/pkg/images/types"
	imageUtils "github.com/stackrox/rox/pkg/images/utils"
	"github.com/stackrox/rox/pkg/kubernetes"
	"github.com/stackrox/rox/sensor/kubernetes/volumes"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	openshiftEncodedDeploymentConfigAnnotation = `openshift.io/encoded-deployment-config`

	megabyte = 1024 * 1024
)

type wrap struct {
	*pkgV1.Deployment
}

func newDeploymentEventFromResource(obj interface{}, action pkgV1.ResourceAction, metaFieldIndex []int, resourceType string, lister podLister) (event *pkgV1.Deployment) {
	objValue := reflect.Indirect(reflect.ValueOf(obj))
	meta, ok := objValue.FieldByIndex(metaFieldIndex).Interface().(metav1.ObjectMeta)
	if !ok {
		logger.Errorf("obj %+v does not have an ObjectMeta field of the correct type", obj)
		return
	}

	// Ignore resources that are owned by another resource.
	// DeploymentConfigs can be owned by TemplateInstance which we don't care about
	if len(meta.OwnerReferences) > 0 && resourceType != kubernetes.DeploymentConfig {
		return
	}

	// This only applies to OpenShift
	if encDeploymentConfig, ok := meta.Annotations[openshiftEncodedDeploymentConfigAnnotation]; ok {
		newMeta, newResourceType, err := extractDeploymentConfig(encDeploymentConfig)
		if err != nil {
			logger.Error(err)
		} else {
			meta = newMeta
			resourceType = newResourceType
		}
	}

	wrap := newWrap(meta, action, resourceType)

	wrap.populateFields(objValue, action, lister)

	return wrap.Deployment
}

func extractDeploymentConfig(encodedDeploymentConfig string) (metav1.ObjectMeta, string, error) {
	// Anonymous struct that only contains the fields we are interested in (note: json.Unmarshal silently ignores
	// fields that are not in the destination object).
	dc := struct {
		Kind     string            `json:"kind"`
		MetaData metav1.ObjectMeta `json:"metadata"`
	}{}
	err := json.Unmarshal([]byte(encodedDeploymentConfig), &dc)
	return dc.MetaData, dc.Kind, err
}

func newWrap(meta metav1.ObjectMeta, action pkgV1.ResourceAction, resourceType string) wrap {
	updatedTime, err := ptypes.TimestampProto(meta.CreationTimestamp.Time)
	if err != nil {
		logger.Error(err)
	}
	return wrap{
		&pkgV1.Deployment{
			Id:          string(meta.UID),
			Name:        meta.Name,
			Type:        resourceType,
			Version:     meta.ResourceVersion,
			Namespace:   meta.Namespace,
			Labels:      meta.Labels,
			Annotations: meta.Annotations,
			UpdatedAt:   updatedTime,
		},
	}
}

func (w *wrap) populateFields(objValue reflect.Value, action pkgV1.ResourceAction, lister podLister) {
	spec := objValue.FieldByName("Spec")
	if reflect.DeepEqual(spec, reflect.Value{}) {
		logger.Errorf("Obj %+v does not have a Spec field", objValue)
		return
	}

	w.populateReplicas(spec)

	var podTemplate v1.PodTemplateSpec
	var ok bool
	if w.GetType() == kubernetes.DeploymentConfig {
		var podTemplatePtr *v1.PodTemplateSpec
		// DeploymentConfig has a pointer to the PodTemplateSpec
		podTemplatePtr, ok = spec.FieldByName("Template").Interface().(*v1.PodTemplateSpec)
		if ok {
			podTemplate = *podTemplatePtr
		}
	} else {
		podTemplate, ok = spec.FieldByName("Template").Interface().(v1.PodTemplateSpec)
	}
	if !ok {
		logger.Errorf("Spec obj %+v does not have a Template field", spec)
		return
	}

	w.populateContainers(podTemplate.Spec)

	if action == pkgV1.ResourceAction_UPDATE_RESOURCE {
		w.populatePodData(spec, lister)
	}
}

func (w *wrap) populateContainers(podSpec v1.PodSpec) {
	w.Deployment.Containers = make([]*pkgV1.Container, len(podSpec.Containers))
	for i := range w.Deployment.Containers {
		w.Deployment.Containers[i] = new(pkgV1.Container)
	}

	w.populateServiceAccount(podSpec)
	w.populateContainerConfigs(podSpec)
	w.populateImages(podSpec)
	w.populateSecurityContext(podSpec)
	w.populateVolumesAndSecrets(podSpec)
	w.populatePorts(podSpec)
	w.populateResources(podSpec)
	w.populateImagePullSecrets(podSpec)
}

func (w *wrap) populateServiceAccount(podSpec v1.PodSpec) {
	w.ServiceAccount = podSpec.ServiceAccountName
}

func (w *wrap) populateImagePullSecrets(podSpec v1.PodSpec) {
	secrets := make([]string, 0, len(podSpec.ImagePullSecrets))
	for _, s := range podSpec.ImagePullSecrets {
		secrets = append(secrets, s.Name)
	}
	w.ImagePullSecrets = secrets
}

func (w *wrap) populateReplicas(spec reflect.Value) {
	replicaField := spec.FieldByName("Replicas")
	if reflect.DeepEqual(replicaField, reflect.Value{}) {
		return
	}

	replicasPointer, ok := replicaField.Interface().(*int32)
	if ok && replicasPointer != nil {
		w.Deployment.Replicas = int64(*replicasPointer)
	}

	replicas, ok := replicaField.Interface().(int32)
	if ok {
		w.Deployment.Replicas = int64(replicas)
	}
}

func (w *wrap) populatePodData(spec reflect.Value, lister podLister) {
	labelSelector := w.getLabelSelector(spec)
	pods := lister.List(labelSelector)
	w.populateImageShas(pods)
	w.populateContainerInstances(pods)
}

func (w *wrap) populateContainerInstances(pods []v1.Pod) {
	for _, p := range pods {
		for i, instance := range containerInstances(p) {
			w.Containers[i].Instances = append(w.Containers[i].Instances, instance)
		}
	}
}

func (w *wrap) populateImageShas(pods []v1.Pod) {
	// This is a map from image full name (eg: stackrox/prevent:latest) to the actual sha of the running image.
	// Note that, if the tag is mutable, there could be multiple shas for a single full name.
	// We just pick an arbitrary one right now, by looking at the running pods and adding the actual sha for this map.
	// This sucks, but it works for now.
	imageNameToSha := make(map[string]string)

	for _, p := range pods {
		for _, c := range p.Status.ContainerStatuses {
			img := imageUtils.GenerateImageFromString(c.Image)
			// If the image string already specifies a sha, we don't need to
			// extract it again from the pod.
			if img.GetName().GetSha() != "" {
				continue
			}

			fullName := img.GetName().GetFullName()
			if fullName == "" {
				logger.Errorf("Couldn't parse either a full name or a sha from image %s of pod %s/%s/%s ",
					c.Image, p.ClusterName, p.Namespace, p.Name)
				continue
			}

			if sha := imageUtils.ExtractImageSha(c.ImageID); sha != "" {
				imageNameToSha[fullName] = imageTypes.NewDigest(sha).Digest()
			}
		}
	}

	for _, c := range w.Deployment.Containers {
		name := c.GetImage().GetName()
		// No need to repopulate the sha if it exists already.
		if name.GetSha() != "" {
			continue
		}
		if sha, ok := imageNameToSha[name.GetFullName()]; ok {
			c.Image.Name.Sha = sha
		}
	}
}

func (w *wrap) getLabelSelector(spec reflect.Value) map[string]string {
	s := spec.FieldByName("Selector")

	// Selector is of map type for replication controller
	if labels, ok := s.Interface().(map[string]string); ok {
		return labels
	}

	// All other resources uses labelSelector.
	if ls, ok := s.Interface().(*metav1.LabelSelector); ok {
		return ls.MatchLabels
	}

	logger.Warnf("unable to get label selector for %+v", spec.Type())
	return make(map[string]string)
}

func (w *wrap) populateContainerConfigs(podSpec v1.PodSpec) {
	for i, c := range podSpec.Containers {

		// Skip if there's nothing to add.
		if len(c.Command) == 0 && len(c.Args) == 0 && len(c.WorkingDir) == 0 && len(c.Env) == 0 && c.SecurityContext == nil {
			continue
		}

		config := &pkgV1.ContainerConfig{
			Command:   c.Command,
			Args:      c.Args,
			Directory: c.WorkingDir,
		}

		envSlice := make([]*pkgV1.ContainerConfig_EnvironmentConfig, len(c.Env))
		for i, env := range c.Env {
			envSlice[i] = &pkgV1.ContainerConfig_EnvironmentConfig{
				Key:   env.Name,
				Value: env.Value,
			}
		}

		config.Env = envSlice

		if s := c.SecurityContext; s != nil {
			if uid := s.RunAsUser; uid != nil {
				config.Uid = *uid
			}
		}

		w.Deployment.Containers[i].Id = w.Deployment.Id + ":" + c.Name
		w.Deployment.Containers[i].Config = config
	}
}

func (w *wrap) populateImages(podSpec v1.PodSpec) {
	for i, c := range podSpec.Containers {
		w.Deployment.Containers[i].Image = imageUtils.GenerateImageFromString(c.Image)
	}
}

func (w *wrap) populateSecurityContext(podSpec v1.PodSpec) {
	for i, c := range podSpec.Containers {
		if s := c.SecurityContext; s != nil {
			sc := &pkgV1.SecurityContext{}

			if p := s.Privileged; p != nil {
				sc.Privileged = *p
			}

			if SELinux := s.SELinuxOptions; SELinux != nil {
				sc.Selinux = &pkgV1.SecurityContext_SELinux{
					User:  SELinux.User,
					Role:  SELinux.Role,
					Type:  SELinux.Type,
					Level: SELinux.Level,
				}
			}

			if capabilities := s.Capabilities; capabilities != nil {
				for _, add := range capabilities.Add {
					sc.AddCapabilities = append(sc.AddCapabilities, string(add))
				}

				for _, drop := range capabilities.Drop {
					sc.DropCapabilities = append(sc.DropCapabilities, string(drop))
				}
			}

			w.Deployment.Containers[i].SecurityContext = sc
		}
	}
}

func (w *wrap) getVolumeSourceMap(podSpec v1.PodSpec) map[string]volumes.VolumeSource {
	volumeSourceMap := make(map[string]volumes.VolumeSource)
	for _, v := range podSpec.Volumes {
		val := reflect.ValueOf(v.VolumeSource)
		for i := 0; i < val.NumField(); i++ {
			f := val.Field(i)
			if !f.IsNil() {
				sourceCreator, ok := volumes.VolumeRegistry[val.Type().Field(i).Name]
				if !ok {
					volumeSourceMap[v.Name] = &volumes.Unimplemented{}
				} else {
					volumeSourceMap[v.Name] = sourceCreator(f.Interface())
				}
			}
		}
	}
	return volumeSourceMap
}

func convertQuantityToCores(q *resource.Quantity) float32 {
	// kubernetes does not like floating point values so they make you jump through hoops
	f, err := strconv.ParseFloat(q.AsDec().String(), 32)
	if err != nil {
		logger.Error(err)
	}
	return float32(f)
}

func convertQuantityToMb(q *resource.Quantity) float32 {
	return float32(float64(q.Value()) / megabyte)
}

func (w *wrap) populateResources(podSpec v1.PodSpec) {
	for i, c := range podSpec.Containers {
		w.Deployment.Containers[i].Resources = &pkgV1.Resources{
			CpuCoresRequest: convertQuantityToCores(c.Resources.Requests.Cpu()),
			CpuCoresLimit:   convertQuantityToCores(c.Resources.Limits.Cpu()),
			MemoryMbRequest: convertQuantityToMb(c.Resources.Requests.Memory()),
			MemoryMbLimit:   convertQuantityToMb(c.Resources.Limits.Memory()),
		}
	}
}

func (w *wrap) populateVolumesAndSecrets(podSpec v1.PodSpec) {
	volumeSourceMap := w.getVolumeSourceMap(podSpec)
	for i, c := range podSpec.Containers {
		for _, v := range c.VolumeMounts {
			sourceVolume, ok := volumeSourceMap[v.Name]
			if !ok {
				sourceVolume = &volumes.Unimplemented{}
			}
			if sourceVolume.Type() == "Secret" {
				w.Deployment.Containers[i].Secrets = append(w.Deployment.Containers[i].Secrets, &pkgV1.EmbeddedSecret{
					Id:   sourceVolume.Source(),
					Name: sourceVolume.Source(),
					Path: v.MountPath,
				})
				continue
			}
			w.Deployment.Containers[i].Volumes = append(w.Deployment.Containers[i].Volumes, &pkgV1.Volume{
				Name:        v.Name,
				Source:      sourceVolume.Source(),
				Destination: v.MountPath,
				ReadOnly:    v.ReadOnly,
				Type:        sourceVolume.Type(),
			})
		}
	}
}

func (w *wrap) populatePorts(podSpec v1.PodSpec) {
	for i, c := range podSpec.Containers {
		for _, p := range c.Ports {
			exposedPort := p.ContainerPort
			// If the port defines a host port, then it is exposed via that port instead of the container port
			if p.HostPort != 0 {
				exposedPort = p.HostPort
			}

			w.Deployment.Containers[i].Ports = append(w.Deployment.Containers[i].Ports, &pkgV1.PortConfig{
				Name:          p.Name,
				ContainerPort: p.ContainerPort,
				ExposedPort:   exposedPort,
				Protocol:      string(p.Protocol),
				Exposure:      pkgV1.PortConfig_INTERNAL,
			})
		}
	}
}
