#!/usr/bin/env bash

set -e

# Launch StackRox Sensor
#
# Deploys the StackRox Sensor into the cluster
#
# Usage:
#   ./sensor.sh
#
# Using a different command:
#     The KUBE_COMMAND environment variable will override the default of kubectl
#
# Examples:
# To use kubectl to create resources (the default):
#     $ ./sensor.sh
# To use another command instead:
#     $ export KUBE_COMMAND='kubectl --context prod-cluster'
#     $ ./sensor.sh

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)"

KUBE_COMMAND=${KUBE_COMMAND:-kubectl}

{{if and (ne .ImageRemote "stackrox-launcher-project-1/stackrox") (ne .ImageRemote "cloud-marketplace/stackrox-launcher-project-1/stackrox-kubernetes-security")}}
${KUBE_COMMAND} get namespace stackrox &>/dev/null || ${KUBE_COMMAND} create namespace stackrox

if ! ${KUBE_COMMAND} get secret/stackrox -n stackrox &>/dev/null; then
  registry_auth="$("${DIR}/docker-auth.sh" -m k8s "{{.ImageRegistry}}")"
  [[ -n "$registry_auth" ]] || { echo >&2 "Unable to get registry auth info." ; exit 1 ; }
  ${KUBE_COMMAND} create --namespace "stackrox" -f - <<EOF
apiVersion: v1
data:
  .dockerconfigjson: ${registry_auth}
kind: Secret
metadata:
  name: stackrox
  namespace: stackrox
type: kubernetes.io/dockerconfigjson
EOF
fi
{{- end}}

if ! ${KUBE_COMMAND} get secret/collector-stackrox -n stackrox &>/dev/null; then
  registry_auth="$("${DIR}/docker-auth.sh" -m k8s "{{.CollectorRegistry}}")"
  [[ -n "$registry_auth" ]] || { echo >&2 "Unable to get registry auth info." ; exit 1 ; }
  ${KUBE_COMMAND} create --namespace "stackrox" -f - <<EOF
apiVersion: v1
data:
  .dockerconfigjson: ${registry_auth}
kind: Secret
metadata:
  name: collector-stackrox
  namespace: stackrox
type: kubernetes.io/dockerconfigjson
EOF
fi

function print_rbac_instructions {
	echo
	echo "Error: Kubernetes RBAC configuration failed."
	echo "Specific errors are listed above."
	echo
	echo "You may need to elevate your privileges first:"
	echo "    ${KUBE_COMMAND} create clusterrolebinding temporary-admin --clusterrole=cluster-admin --user you@example.com"
	echo
	echo "(Be sure to use the full username your cluster knows for you.)"
	echo
	echo "Then, rerun this script."
	echo
	echo "Finally, revoke your temporary privileges:"
	echo "    ${KUBE_COMMAND} delete clusterrolebinding temporary-admin"
	echo
	echo "Contact your cluster administrator if you cannot obtain sufficient permission."
	exit 1
}

echo "Creating sensor RBAC roles..."
${KUBE_COMMAND} apply -f "$DIR/sensor-rbac.yaml" || print_rbac_instructions
echo "Creating sensor network policies..."
${KUBE_COMMAND} apply -f "$DIR/sensor-netpol.yaml" || exit 1
echo "Creating sensor pod security policies..."
${KUBE_COMMAND} apply -f "$DIR/sensor-pod-security.yaml"

{{ if .CreateUpgraderSA }}
echo "Creating upgrader service account"
${KUBE_COMMAND} apply -f "${DIR}/upgrader-serviceaccount.yaml" || print_rbac_instructions
{{- end }}

{{- if .AdmissionController }}
echo "Creating admission controller secrets..."
${KUBE_COMMAND} apply -f "$DIR/admission-controller-secret.yaml"
echo "Creating admission controller RBAC roles..."
${KUBE_COMMAND} apply -f "$DIR/admission-controller-rbac.yaml" || print_rbac_instructions
echo "Creating admission controller network policies..."
${KUBE_COMMAND} apply -f "$DIR/admission-controller-netpol.yaml"
echo "Creating admission controller pod security policies..."
${KUBE_COMMAND} apply -f "$DIR/admission-controller-pod-security.yaml"
echo "Creating admission controller deployment..."
${KUBE_COMMAND} apply -f "$DIR/admission-controller.yaml"
{{- else }}
echo "Deleting admission controller webhook, if it exists"
${KUBE_COMMAND} delete validatingwebhookconfiguration stackrox --ignore-not-found
{{- end }}

echo "Creating secrets for sensor..."
${KUBE_COMMAND} apply -f "$DIR/sensor-secret.yaml"

if [[ -f "$DIR/additional-ca-sensor.yaml" ]]; then
  echo "Creating secret for additional CAs for sensor..."
  ${KUBE_COMMAND} apply -f "$DIR/additional-ca-sensor.yaml"
fi

echo "Creating collector secrets..."
${KUBE_COMMAND} apply -f "$DIR/collector-secret.yaml"
echo "Creating collector RBAC roles..."
${KUBE_COMMAND} apply -f "$DIR/collector-rbac.yaml" || print_rbac_instructions
echo "Creating collector network policies..."
${KUBE_COMMAND} apply -f "$DIR/collector-netpol.yaml"
echo "Creating collector pod security policies..."
${KUBE_COMMAND} apply -f "$DIR/collector-pod-security.yaml"
echo "Creating collector daemon set..."
${KUBE_COMMAND} apply -f "$DIR/collector.yaml"

echo "Creating sensor deployment..."
${KUBE_COMMAND} apply -f "$DIR/sensor.yaml"

{{ if not .CreateUpgraderSA }}
if [[ -f "${DIR}/upgrader-serviceaccount.yaml" ]]; then
    printf "%s\n\n%s\n" "Did not create the upgrader service account. To create it later, please run" "${KUBE_COMMAND} apply -f \"${DIR}/upgrader-serviceaccount.yaml\""
fi
{{- end }}
