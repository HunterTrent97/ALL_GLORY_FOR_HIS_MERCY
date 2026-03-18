#!/bin/bash
set -e

echo "🚀 Kind Cluster + ngrok Setup"
echo "=============================="
echo ""

# Step 1:  Create Kind cluster
echo "📦 Creating Kind cluster (1 control-plane + 2 workers)..."
kind create cluster --config kind-cluster.yaml

# Wait for nodes
echo "⏳ Waiting for nodes to be ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=300s

echo ""
echo "✅ Cluster created successfully!"
kubectl get nodes
echo ""

# Step 2: Set up RBAC for remote access
echo "🔐 Setting up RBAC for remote access..."

# Create service account
kubectl create serviceaccount ngrok 2>/dev/null || echo "Service
account 'ngrok' already exists"

# Create cluster role binding (admin privileges for simplicity)
kubectl create clusterrolebinding ngrok-admin-binding \
  --clusterrole=admin \
  --serviceaccount=default:ngrok 2>/dev/null || echo
"ClusterRoleBinding already exists"

# Create token and configure kubectl
echo "📝 Creating service account token..."
TOKEN=$(kubectl create token ngrok --duration=8760h)  # 1 year token

# Add the service account to kubeconfig
kubectl config set-credentials ngrok --token="$TOKEN"

echo "✓ RBAC configured"