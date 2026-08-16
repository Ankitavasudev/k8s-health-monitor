#!/bin/bash
# k8s-health-check.sh - Quick Kubernetes cluster health checker
# Usage: ./k8s-health-check.sh [namespace]

set -e

NAMESPACE=${1:-default}

echo "=========================================="
echo "  Kubernetes Cluster Health Check"
echo "=========================================="
echo ""

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl is not installed or not in PATH"
    exit 1
fi

echo "📋 Checking cluster status..."
if kubectl cluster-info &> /dev/null; then
    echo "✅ Cluster is reachable"
else
    echo "❌ Cannot reach cluster"
    exit 1
fi

echo ""
echo "📦 Pods in namespace: $NAMESPACE"
kubectl get pods -n $NAMESPACE -o wide 2>/dev/null || echo "No pods found"

echo ""
echo "🔍 Unhealthy Pods:"
UNHEALTHY=$(kubectl get pods -n $NAMESPACE --field-selector=status.phase!=Running,status.phase!=Succeeded -o name 2>/dev/null)
if [ -z "$UNHEALTHY" ]; then
    echo "✅ All pods are healthy"
else
    echo "$UNHEALTHY"
fi

echo ""
echo "📊 Resource Usage:"
kubectl top nodes 2>/dev/null || echo "Metrics server not available"

echo ""
echo "🔗 Services:"
kubectl get services -n $NAMESPACE 2>/dev/null || echo "No services found"

echo ""
echo "📦 Deployments:"
kubectl get deployments -n $NAMESPACE 2>/dev/null || echo "No deployments found"

echo ""
echo "🔄 Replicasets:"
kubectl get replicasets -n $NAMESPACE 2>/dev/null || echo "No replicasets found"

echo ""
echo "=========================================="
echo "  Health Check Complete"
echo "=========================================="
