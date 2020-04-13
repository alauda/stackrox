#!/usr/bin/env bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)"

# assuming deployment on Kubernetes in Docker for Mac or Minikube
export RUNTIME_SUPPORT="${RUNTIME_SUPPORT:-kernel-module}"
export MONITORING_SUPPORT="${MONITORING_SUPPORT:-false}"

$DIR/deploy.sh
