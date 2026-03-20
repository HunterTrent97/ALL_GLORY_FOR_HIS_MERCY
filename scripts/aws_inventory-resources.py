#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
import boto3
import yaml

# =========================
# 🔒 HARD SECURITY CONFIG
# =========================
ALLOWED_PREFIXES = ("describe_", "list_", "get_")
ALLOWED_KUBECTL_RESOURCES = {"pods", "nodes"}

READ_ONLY_MODE = True


def enforce_read_only(method):
    m = method.lower()
    if not any(m.startswith(p) for p in ALLOWED_PREFIXES):
        raise RuntimeError(f"[SECURITY] BLOCKED METHOD: {method}")


def safe_call(client, method, **kwargs):
    enforce_read_only(method)
    return getattr(client, method)(**kwargs)


def paginate(client, method, key, **kwargs):
    enforce_read_only(method)
    paginator = client.get_paginator(method)
    results = []
    for page in paginator.paginate(**kwargs):
        results.extend(page.get(key, []))
    return results


# =========================
# CONFIG / HELPERS
# =========================
def load_config(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)


def match_any(patterns, value):
    return any(p.lower() in value.lower() for p in patterns)


def name_tag(tags):
    if not tags:
        return ""
    for t in tags:
        if t.get("Key") == "Name":
            return t.get("Value", "")
    return ""


def print_result(label, target, matches):
    if matches:
        print(f"[{label}] {target}: FOUND -> {matches}")
    else:
        print(f"[{label}] {target}: NOT FOUND")


# =========================
# 🔒 KUBECTL LOCKDOWN
# =========================
def run_kubectl(context, resource):
    if resource not in ALLOWED_KUBECTL_RESOURCES:
        raise RuntimeError(f"[SECURITY] kubectl resource blocked: {resource}")

    cmd = ["kubectl", "--context", context, "get", resource, "-o", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[ERROR] kubectl failed for {context}: {result.stderr}")
        return {}

    return json.loads(result.stdout) if result.stdout else {}


# =========================
# REGION HANDLING
# =========================
def get_regions(session, default_region, scan_all):
    if not scan_all:
        return [default_region]

    ec2 = session.client("ec2", region_name=default_region)
    regions = paginate(ec2, "describe_regions", "Regions")
    return [r["RegionName"] for r in regions]


# =========================
# SERVICE CHECKS
# =========================
def check_s3(session, cfg):
    print("\n=== S3 ===")
    s3 = session.client("s3")
    buckets = safe_call(s3, "list_buckets").get("Buckets", [])
    names = [b["Name"] for b in buckets]

    for t in cfg.get("match_names", []):
        print_result("S3", t, [n for n in names if match_any([t], n)])


def check_ec2(session, region, cfg):
    print(f"\n=== EC2 ({region}) ===")
    ec2 = session.client("ec2", region_name=region)
    res = paginate(ec2, "describe_instances", "Reservations")

    names = []
    for r in res:
        for i in r.get("Instances", []):
            n = name_tag(i.get("Tags"))
            if n:
                names.append(n)

    for t in cfg.get("match_name_tags", []):
        print_result("EC2", t, [n for n in names if match_any([t], n)])


def check_rds(session, region, cfg):
    print(f"\n=== RDS ({region}) ===")
    rds = session.client("rds", region_name=region)
    dbs = paginate(rds, "describe_db_instances", "DBInstances")

    ids = [d["DBInstanceIdentifier"] for d in dbs]
    for t in cfg.get("match_identifiers", []):
        print_result("RDS", t, [i for i in ids if match_any([t], i)])


def check_eks(session, region, cfg):
    print(f"\n=== EKS ({region}) ===")
    eks = session.client("eks", region_name=region)

    clusters = paginate(eks, "list_clusters", "clusters")
    matched = []

    for t in cfg.get("match_clusters", []):
        m = [c for c in clusters if match_any([t], c)]
        matched.extend(m)
        print_result("EKS CLUSTER", t, m)

    for c in matched:
        ngs = paginate(eks, "list_nodegroups", "nodegroups", clusterName=c)
        for t in cfg.get("match_nodegroups", []):
            print_result(f"EKS NG ({c})", t, [n for n in ngs if match_any([t], n)])

    return matched


def eks_deep(session, region, cfg):
    print(f"\n=== EKS DEEP ({region}) ===")

    ec2 = session.client("ec2", region_name=region)

    enis = paginate(ec2, "describe_network_interfaces", "NetworkInterfaces")
    print(f"[ENI] total={len(enis)}")

    subs = paginate(ec2, "describe_subnets", "Subnets")
    for s in subs:
        print(f"[SUBNET] {s['SubnetId']} available={s['AvailableIpAddressCount']}")

    for ctx in cfg.get("kubectl_contexts", []):
        print(f"\n[kubectl] {ctx}")

        pods = run_kubectl(ctx, "pods").get("items", [])
        nodes = run_kubectl(ctx, "nodes").get("items", [])

        print(f"Pods={len(pods)} Nodes={len(nodes)}")


def check_vpc(session, region, cfg):
    print(f"\n=== VPC ({region}) ===")
    ec2 = session.client("ec2", region_name=region)

    vpcs = paginate(ec2, "describe_vpcs", "Vpcs")
    for t in cfg.get("match_vpc_names", []):
        matches = []
        for v in vpcs:
            n = name_tag(v.get("Tags"))
            if match_any([t], n):
                matches.append(v["VpcId"])
        print_result("VPC", t, matches)


def check_ecr(session, region, cfg):
    print(f"\n=== ECR ({region}) ===")
    ecr = session.client("ecr", region_name=region)

    repos = paginate(ecr, "describe_repositories", "repositories")
    names = [r["repositoryName"] for r in repos]

    for t in cfg.get("match_repositories", []):
        print_result("ECR", t, [n for n in names if match_any([t], n)])


def check_kms(session, region, cfg):
    print(f"\n=== KMS ({region}) ===")
    kms = session.client("kms", region_name=region)

    aliases = paginate(kms, "list_aliases", "Aliases")
    names = [a["AliasName"] for a in aliases if "AliasName" in a]

    for t in cfg.get("match_aliases", []):
        print_result("KMS", t, [n for n in names if match_any([t], n)])


def check_elb(session, region, cfg):
    print(f"\n=== ELB ({region}) ===")
    elb = session.client("elbv2", region_name=region)

    lbs = paginate(elb, "describe_load_balancers", "LoadBalancers")
    names = [l["LoadBalancerName"] for l in lbs]

    for t in cfg.get("match_load_balancer_names", []):
        print_result("LB", t, [n for n in names if match_any([t], n)])


# =========================
# MAIN
# =========================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)

    args = parser.parse_args()

    if not READ_ONLY_MODE:
        print("[SECURITY] Read-only mode disabled — aborting")
        sys.exit(1)

    cfg = load_config(args.config)
    region = cfg["global"]["region"]
    scan_all = cfg["global"].get("scan_all_regions", False)

    session = boto3.Session(region_name=region)
    regions = get_regions(session, region, scan_all)

    resources = cfg.get("resources", {})

    print("\n=== READ-ONLY AWS INVENTORY ===")
    print("[MODE] STRICT READ-ONLY (no write APIs possible)")

    if "s3" in resources:
        check_s3(session, resources["s3"])

    for r in regions:
        if "ec2" in resources:
            check_ec2(session, r, resources["ec2"])

        if "rds" in resources:
            check_rds(session, r, resources["rds"])

        if "eks" in resources:
            check_eks(session, r, resources["eks"])

            if "deep_inspection" in resources["eks"]:
                eks_deep(session, r, resources["eks"]["deep_inspection"])

        if "vpc" in resources:
            check_vpc(session, r, resources["vpc"])

        if "ecr" in resources:
            check_ecr(session, r, resources["ecr"])

        if "kms" in resources:
            check_kms(session, r, resources["kms"])

        if "elb" in resources:
            check_elb(session, r, resources["elb"])


if __name__ == "__main__":
    main()