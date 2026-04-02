#!/usr/bin/env bash
set -euo pipefail
shopt -s expand_aliases

source ~/.bashrc 2>/dev/null || true
source ~/.bash_profile 2>/dev/null || true

CONFIG=${1:-sync_config.yaml}

while true; do
  echo "Resetting creds..."
  demote || true   # 🔥 ALWAYS FIRST
  promote          # 🔥 ALWAYS SECOND

  python3 s3_massive_sync.py --config "$CONFIG"
  rc=$?

  if [[ $rc -eq 0 ]]; then
    echo "Done"
    exit 0
  fi

  if [[ $rc -eq 2 ]]; then
    echo "Token expired, re-authenticating..."
    continue
  fi

  echo "Unexpected failure"
  exit $rc
done
