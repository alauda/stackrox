#!/bin/bash


export CENTRAL_NAMESPACE=${CENTRAL_NAMESPACE:-stackrox}
export SENSOR_NAMESPACE=${SENSOR_NAMESPACE:-stackrox}

kubectl -n "$SENSOR_NAMESPACE" patch svc/sensor -p '{"spec":{"ports":[{"name":"monitoring","port":9090,"protocol":"TCP","targetPort":9090}]}}'
kubectl -n "$CENTRAL_NAMESPACE" patch svc/central -p '{"spec":{"ports":[{"name":"monitoring","port":9090,"protocol":"TCP","targetPort":9090}]}}'
kubectl -n "$SENSOR_NAMESPACE" patch daemonset/collector --type='json' -p='[{"op": "add", "path": "/spec/template/spec/containers/1/ports", "value":[{"containerPort":9091,"name":"cmonitor","protocol":"TCP"}]}]'

# Modify network policies to allow ingress
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  labels:
    app.kubernetes.io/name: stackrox
  name: allow-monitoring-central
  namespace: "$CENTRAL_NAMESPACE"
spec:
  ingress:
  - ports:
    - port: 9090
      protocol: TCP
  podSelector:
    matchExpressions:
    - {key: app, operator: In, values: [central]}
  policyTypes:
  - Ingress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  labels:
    app.kubernetes.io/name: stackrox
  name: allow-monitoring-sensor
  namespace: "$SENSOR_NAMESPACE"
spec:
  ingress:
  - ports:
    - port: 9090
      protocol: TCP
  podSelector:
    matchExpressions:
    - {key: app, operator: In, values: [sensor]}
  policyTypes:
  - Ingress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  labels:
    app.kubernetes.io/name: stackrox
  name: allow-compliance-monitoring
  namespace: "$SENSOR_NAMESPACE"
spec:
  ingress:
  - ports:
    - port: 9091
      protocol: TCP
  podSelector:
    matchLabels:
      app: collector
  policyTypes:
  - Ingress
EOF
