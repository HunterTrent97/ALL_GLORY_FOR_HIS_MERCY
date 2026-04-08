#!/usr/bin/env bash

# Fail on errors, undefined vars, and pipe failures
set -euo pipefail

# Allow aliases like promote/demote
shopt -s expand_aliases

# Load shell config so aliases exist
source ~/.bashrc 2>/dev/null || true
source ~/.bash_profile 2>/dev/null || true

# Config file input (default if not provided)
CONFIG=${1:-sync_config.yaml}

# Infinite loop to handle retries and token refresh
while true; do
  echo "Resetting creds..."

  # 🔹 Clear any existing AWS credentials (prevents stale token issues)
  demote || true

  # 🔹 Re-authenticate (your custom logic / SSO / assume-role)
  promote

  echo "Verifying identity..."

  # 🔹 Ensure credentials are valid before running anything
  aws sts get-caller-identity || {
    echo "Auth failed"
    exit 1
  }

  echo "Starting sync process..."

  # 🔹 Run Python wrapper (which runs CLI sync)
  python3 s3_cli_sync.py --config "$CONFIG"
  rc=$?

  # 🔹 Success case
  if [[ $rc -eq 0 ]]; then
    echo "Sync complete"
    exit 0
  fi

  # 🔹 Token expired → re-run loop (demote + promote again)
  if [[ $rc -eq 2 ]]; then
    echo "Token expired → reauthenticating..."
    continue
  fi

  # 🔹 Any other failure → stop completely
  echo "Unexpected failure"
  exit $rc
done
