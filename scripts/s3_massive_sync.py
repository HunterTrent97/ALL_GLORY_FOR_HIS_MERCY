#!/usr/bin/env python3

import subprocess
import yaml
import sys
import time


# =========================
# Load YAML config
# =========================
def load_cfg(path):
    with open(path) as f:
        return yaml.safe_load(f)


# =========================
# Run shell command
# =========================
def run(cmd):
    # Executes AWS CLI command
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


# =========================
# Detect token/auth errors
# =========================
def is_auth_error(output):
    return any(x in output for x in [
        "ExpiredToken",
        "expired",
        "InvalidClientTokenId",
        "UnrecognizedClientException",
        "SSOProviderInvalidToken"
    ])


# =========================
# Detect retryable errors
# =========================
def is_retryable(output):
    return any(x in output for x in [
        "RequestTimeout",
        "Throttling",
        "SlowDown",
        "500",
        "502",
        "503",
        "504"
    ])


# =========================
# Detect fatal errors
# =========================
def is_fatal(output):
    return any(x in output for x in [
        "AccessDenied",
        "NoSuchBucket",
        "403",
        "404"
    ])


# =========================
# Main execution
# =========================
def main():
    if len(sys.argv) < 3:
        print("Usage: python s3_cli_sync.py --config <file>")
        sys.exit(1)

    # Load config file
    cfg_path = sys.argv[2]
    cfg = load_cfg(cfg_path)

    region = cfg["aws"]["region"]

    # Build S3 paths
    src = f"s3://{cfg['source']['bucket']}/{cfg['source']['prefix']}"
    dst = f"s3://{cfg['destination']['bucket']}/{cfg['destination']['prefix']}"

    # Build CLI sync command
    cmd = f"aws s3 sync {src} {dst} --region {region}"

    # Add dry-run if enabled
    if cfg["execution"]["dry_run"]:
        cmd += " --dryrun"

    retries = cfg["execution"]["retryable_attempts"]
    base = cfg["execution"]["retry_backoff_base_seconds"]
    fail_log = cfg["execution"]["fail_log_file"]

    attempt = 1

    while attempt <= retries:
        print(f"\n=== ATTEMPT {attempt}/{retries} ===")
        print(cmd)

        code, out, err = run(cmd)
        combined = out + err

        # =========================
        # SUCCESS
        # =========================
        if code == 0:
            print("Sync successful")
            sys.exit(0)

        print("Sync failed:")
        print(combined)

        # =========================
        # AUTH / TOKEN ERROR
        # =========================
        if is_auth_error(combined):
            print("Token expired or invalid → exiting for reauth")
            sys.exit(2)   # Shell will re-run promote

        # =========================
        # FATAL ERRORS (STOP)
        # =========================
        if is_fatal(combined):
            print("Fatal error — stopping")

            with open(fail_log, "a") as f:
                f.write(combined + "\n")

            sys.exit(1)

        # =========================
        # RETRYABLE ERRORS
        # =========================
        if is_retryable(combined):
            sleep_time = min(60, base * (2 ** attempt))
            print(f"Retrying in {sleep_time}s...")
            time.sleep(sleep_time)
            attempt += 1
            continue

        # =========================
        # UNKNOWN ERROR
        # =========================
        print("Unknown error — logging + exit")

        with open(fail_log, "a") as f:
            f.write(combined + "\n")

        sys.exit(1)

    print("Max retries reached")
    sys.exit(1)


if __name__ == "__main__":
    main()
