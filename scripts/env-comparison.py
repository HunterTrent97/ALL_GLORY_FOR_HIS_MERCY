#!/usr/bin/env python3
"""
eks_two_env_inventory.py

Secure local, read-only inventory + delta + findings generator for two Amazon EKS
environments in one AWS account. Runs from a laptop/GFE using boto3's DEFAULT
credential chain (NO profile prompt; NO embedded credentials).

Output: one .xlsx workbook with tabs:
  - SpartaET
  - Sparta-Staging
  - Deltas
  - Findings

Required by spec:
  - Python 3.9+
  - boto3/botocore
  - pandas + xlsxwriter (preferred) OR pandas + openpyxl (fallback)
  - ipaddress (stdlib)
Optional:
  - kubernetes python client when using --kubeconfig mode

SECURITY:
  - Read-only AWS APIs (Describe/List/Get only).
  - Sanitized terminal output in --dry-run (mask 12-digit account IDs).
  - No IAM policy documents or EC2 user-data printed or exported.

WHERE TO EDIT CLUSTER NAMES (placeholders):
  - CLUSTER_NAME_SPARTA_ET
  - CLUSTER_NAME_SPARTA_STAGING
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

import pandas as pd


# =============================================================================
# USER-EDITABLE PLACEHOLDERS
# =============================================================================
# Fill these in once the script is on your laptop (per your requirement).
CLUSTER_NAME_SPARTA_ET = ""         # <-- EDIT ME: e.g. "sparta-et-eks"
CLUSTER_NAME_SPARTA_STAGING = ""    # <-- EDIT ME: e.g. "sparta-staging-eks"

DEFAULT_LOW_FREE_IP_THRESHOLD = 64  # <-- EDIT ME or override with --threshold

# =============================================================================
# Logging
# =============================================================================
LOG = logging.getLogger("eks_two_env_inventory")


# =============================================================================
# Sanitization + Sparta naming rule (unit-testable helpers)
# =============================================================================
_ACCOUNT_ID_RE = re.compile(r"\b(\d{12})\b")


def mask_account_id(account_id: str) -> str:
    """Mask a 12-digit account ID: 123456789012 -> 1234****9012."""
    if not account_id or not re.fullmatch(r"\d{12}", account_id):
        return account_id
    return f"{account_id[:4]}****{account_id[-4:]}"


def sanitize_text(text: Any, account_id: str) -> str:
    """
    Sanitize terminal output by masking 12-digit sequences (account IDs in ARNs, etc).
    """
    s = "" if text is None else str(text)
    if account_id and re.fullmatch(r"\d{12}", account_id):
        s = s.replace(account_id, mask_account_id(account_id))
    return _ACCOUNT_ID_RE.sub(lambda m: mask_account_id(m.group(1)), s)


def sparta_name_rule(name: str) -> str:
    """
    Sparta naming rule (case-insensitive):

    - name contains 'et' AND also contains 'stage' or 'staging' => Sparta-Staging
    - name contains 'et' => SpartaET
    - else => Unknown
    """
    n = (name or "").lower()
    if "et" in n and ("stage" in n or "staging" in n):
        return "Sparta-Staging"
    if "et" in n:
        return "SpartaET"
    return "Unknown"


def should_include_resource(env_tab: str, env_by_rule: str) -> bool:
    """
    Explicit requirement: For SpartaET env, EXCLUDE resources whose naming-class is Sparta-Staging
    (i.e., name contains both 'et' and 'stage'/'staging' => belongs to Sparta-Staging).
    """
    if env_tab == "SpartaET" and env_by_rule == "Sparta-Staging":
        return False
    return True


def tags_list_to_dict(tags: Optional[List[Dict[str, Any]]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not tags:
        return out
    for t in tags:
        k = t.get("Key")
        v = t.get("Value")
        if isinstance(k, str):
            out[k] = "" if v is None else str(v)
    return out


def tags_to_json(tags: Dict[str, str]) -> str:
    if not tags:
        return ""
    return json.dumps(dict(sorted(tags.items())), sort_keys=True)


def get_name_tag(tags: Dict[str, str]) -> str:
    return tags.get("Name", "")


def chunked(seq: Sequence[Any], size: int) -> Iterable[Sequence[Any]]:
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def iso_utc_now() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def total_usable_ipv4_in_subnet(cidr: str) -> Optional[int]:
    """
    AWS reserves 5 IPv4 addresses per subnet; usable = total - 5.
    """
    if not cidr:
        return None
    net = ipaddress.ip_network(cidr)
    if net.version != 4:
        return None
    usable = max(int(net.num_addresses) - 5, 0)
    return usable


def subnet_ip_metrics(cidr: str, available: Optional[int]) -> Dict[str, Any]:
    total_usable = total_usable_ipv4_in_subnet(cidr)
    if total_usable is None or available is None:
        return {"TotalUsableIps": total_usable, "AvailableIps": available, "UsedIps": None, "PctUsed": None}
    used = max(total_usable - int(available), 0)
    pct = round((used / total_usable) * 100.0, 2) if total_usable else None
    return {"TotalUsableIps": total_usable, "AvailableIps": int(available), "UsedIps": used, "PctUsed": pct}


# =============================================================================
# AWS client bundle + retry config
# =============================================================================
@dataclass(frozen=True)
class AwsClients:
    sts: Any
    eks: Any
    ec2: Any
    autoscaling: Any
    iam: Any


def build_clients() -> AwsClients:
    """
    Build boto3 clients using DEFAULT credential chain and a retry configuration.
    No profile prompts. Region is taken from standard AWS config/env resolution.
    """
    cfg = Config(
        retries={"mode": "standard", "total_max_attempts": 10},
        connect_timeout=10,
        read_timeout=60,
        user_agent_extra="eks-two-env-inventory-local",
    )
    session = boto3.session.Session()
    # Region must be resolved by environment/config; otherwise AWS will raise.
    return AwsClients(
        sts=session.client("sts", config=cfg),
        eks=session.client("eks", config=cfg),
        ec2=session.client("ec2", config=cfg),
        autoscaling=session.client("autoscaling", config=cfg),
        iam=session.client("iam", config=cfg),
    )


_THROTTLE_CODES = {
    "Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyRequestsException", "RateExceeded"
}


def aws_call(fn, *args, **kwargs):
    """
    Wrapper for AWS calls. botocore retries already help, but this adds a small
    exponential backoff if throttling persists.
    """
    max_tries = 5
    base_sleep = 0.5
    for attempt in range(1, max_tries + 1):
        try:
            return fn(*args, **kwargs)
        except ClientError as e:
            code = (e.response.get("Error") or {}).get("Code", "")
            if code in _THROTTLE_CODES and attempt < max_tries:
                sleep_s = base_sleep * (2 ** (attempt - 1))
                LOG.warning("Throttled (%s); backing off %.1fs...", code, sleep_s)
                time.sleep(sleep_s)
                continue
            raise


def paginate(client: Any, op_name: str, result_key: str, **kwargs) -> List[Any]:
    """
    Paginate an AWS operation using boto3 paginator when supported.
    """
    if client.can_paginate(op_name):
        paginator = client.get_paginator(op_name)
        out: List[Any] = []
        for page in aws_call(paginator.paginate, **kwargs):
            out.extend(page.get(result_key, []))
        return out
    resp = aws_call(getattr(client, op_name), **kwargs)
    return resp.get(result_key, [])


# =============================================================================
# Inventory record model (stable schema)
# =============================================================================
INVENTORY_COLUMNS = [
    "EnvTab", "EnvByNameRule", "Scope", "ResourceType",
    "Name", "Description",
    "Id", "Arn",
    "Region", "AccountMasked",
    "VpcId", "SubnetId", "AvailabilityZone",
    "CidrBlock", "TotalUsableIps", "AvailableIps", "UsedIps", "PctUsed",
    "AutoScalingGroupName",
    "InstanceId", "InstanceType", "InstanceState",
    "EniCountAttachedToInstance",
    "EniId", "EniAttachmentInstanceId", "EniPrivateIpCount", "EniSecondaryIpCount",
    "SecurityGroupIds", "RouteTableIds", "NetworkAclIds", "VpcEndpointIds", "NatGatewayIds", "InternetGatewayIds",
    "TagsJson", "DetailsJson",
]


def record(**kwargs) -> Dict[str, Any]:
    row = {c: "" for c in INVENTORY_COLUMNS}
    row.update(kwargs)
    return row


FINDING_COLUMNS = [
    "FindingId", "EnvTab", "Severity", "Category",
    "ResourceType", "ResourceId", "ResourceName",
    "Evidence", "Hypothesis", "RecommendedChecks",
]


def finding(**kwargs) -> Dict[str, Any]:
    row = {c: "" for c in FINDING_COLUMNS}
    row.update(kwargs)
    return row


DELTA_COLUMNS = [
    "Domain", "Key", "ResourceType", "Field",
    "SpartaET", "Sparta-Staging", "DeltaSummary",
]


# =============================================================================
# Optional kubeconfig collectors (only if --kubeconfig is provided)
# =============================================================================
class KubeCollectors:
    """
    Optional read-only Kubernetes collectors:
      - aws-node DaemonSet env vars
      - amazon-vpc-cni ConfigMap
      - ENIConfig CRs
      - Karpenter CRs (best-effort on common group/version/plural combos)

    Only runs when --kubeconfig is provided.
    """
    def __init__(self, kubeconfig: str, kubecontext: str):
        self.kubeconfig = kubeconfig
        self.kubecontext = kubecontext or None
        from kubernetes import client as k8s_client  # type: ignore
        from kubernetes import config as k8s_config  # type: ignore
        from kubernetes.client.rest import ApiException  # type: ignore
        self.k8s_client = k8s_client
        self.k8s_config = k8s_config
        self.ApiException = ApiException
        self.k8s_config.load_kube_config(config_file=self.kubeconfig, context=self.kubecontext)

    def collect(self, env_tab: str, account_id: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        recs: List[Dict[str, Any]] = []
        fnds: List[Dict[str, Any]] = []

        # aws-node DaemonSet
        try:
            apps = self.k8s_client.AppsV1Api()
            ds = apps.read_namespaced_daemon_set(name="aws-node", namespace="kube-system")
            containers = ds.spec.template.spec.containers or []  # type: ignore
            envs: Dict[str, str] = {}
            image = ""
            if containers:
                image = containers[0].image or ""
                for e in (containers[0].env or []):  # type: ignore
                    if e.name:
                        envs[e.name] = e.value or ""
            name = "aws-node"
            env_by_rule = sparta_name_rule(name)
            recs.append(record(
                EnvTab=env_tab,
                EnvByNameRule=env_by_rule,
                Scope="Kubeconfig",
                ResourceType="K8sDaemonSet",
                Name=name,
                Description="Amazon VPC CNI DaemonSet; env vars reflect IPAM/prefix/Pod ENI settings",
                Id="kube-system/aws-node",
                AccountMasked=mask_account_id(account_id),
                DetailsJson=json.dumps({"KubeContext": self.kubecontext or "", "Image": image, "EnvVars": envs}, default=str),
            ))

            # High-signal env vars for findings
            if envs.get("ENABLE_PREFIX_DELEGATION", "").lower() == "true":
                fnds.append(finding(
                    FindingId=f"{env_tab}-prefix-delegation-enabled",
                    EnvTab=env_tab,
                    Severity="Info",
                    Category="VPC_CNI_PrefixDelegation",
                    ResourceType="K8sDaemonSet",
                    ResourceId="kube-system/aws-node",
                    ResourceName="aws-node",
                    Evidence="ENABLE_PREFIX_DELEGATION=true",
                    Hypothesis="Prefix delegation increases pod IP capacity but can fail when no contiguous /28 blocks exist (fragmentation).",
                    RecommendedChecks="If you see InsufficientCidrBlocks, consider subnet CIDR reservations or new subnets for prefixes.",
                ))

            if envs.get("ENABLE_POD_ENI", "").lower() == "true":
                fnds.append(finding(
                    FindingId=f"{env_tab}-sgpp-enabled",
                    EnvTab=env_tab,
                    Severity="Info",
                    Category="SecurityGroupsForPods",
                    ResourceType="K8sDaemonSet",
                    ResourceId="kube-system/aws-node",
                    ResourceName="aws-node",
                    Evidence="ENABLE_POD_ENI=true",
                    Hypothesis="Security groups for Pods uses trunk/branch ENIs and changes ENI/IP consumption patterns.",
                    RecommendedChecks="Correlate trunk/branch ENIs in VPC with subnet free IPs; ensure VPC Resource Controller policy is present on cluster role.",
                ))

            warm_keys = ["WARM_ENI_TARGET", "WARM_IP_TARGET", "MINIMUM_IP_TARGET", "WARM_PREFIX_TARGET"]
            warm_present = {k: envs.get(k, "") for k in warm_keys if envs.get(k)}
            if warm_present:
                fnds.append(finding(
                    FindingId=f"{env_tab}-warm-pool-settings",
                    EnvTab=env_tab,
                    Severity="Info",
                    Category="VPC_CNI_WarmPool",
                    ResourceType="K8sDaemonSet",
                    ResourceId="kube-system/aws-node",
                    ResourceName="aws-node",
                    Evidence=f"Warm pool env vars present: {warm_present}",
                    Hypothesis="Warm pools reserve IP capacity preemptively, increasing steady-state subnet IP consumption.",
                    RecommendedChecks="Validate warm pool targets vs workload/scale patterns, especially during patch surge.",
                ))

        except Exception as e:
            LOG.warning("Kubeconfig mode: unable to read aws-node daemonset: %s", e)

        # amazon-vpc-cni ConfigMap (if present)
        try:
            core = self.k8s_client.CoreV1Api()
            cm = core.read_namespaced_config_map(name="amazon-vpc-cni", namespace="kube-system")
            name = "amazon-vpc-cni"
            recs.append(record(
                EnvTab=env_tab,
                EnvByNameRule=sparta_name_rule(name),
                Scope="Kubeconfig",
                ResourceType="K8sConfigMap",
                Name=name,
                Description="VPC CNI config map (may include warm/min/prefix keys)",
                Id="kube-system/amazon-vpc-cni",
                AccountMasked=mask_account_id(account_id),
                DetailsJson=json.dumps({"Data": cm.data or {}}, default=str),
            ))
        except Exception:
            pass

        # ENIConfig CRs and Karpenter CRs (best effort)
        recs.extend(self._try_list_cr(env_tab, account_id, "crd.k8s.amazonaws.com", "v1alpha1", "eniconfigs", "K8sENIConfig", "ENIConfig custom resources"))
        for group, version, plural, rtype in [
            ("karpenter.sh", "v1beta1", "nodepools", "K8sKarpenterNodePool"),
            ("karpenter.sh", "v1beta1", "nodeclaims", "K8sKarpenterNodeClaim"),
            ("karpenter.k8s.aws", "v1beta1", "ec2nodeclasses", "K8sKarpenterEC2NodeClass"),
            ("karpenter.sh", "v1alpha5", "provisioners", "K8sKarpenterProvisioner"),
            ("karpenter.k8s.aws", "v1alpha1", "awsnodetemplates", "K8sKarpenterAWSNodeTemplate"),
        ]:
            recs.extend(self._try_list_cr(env_tab, account_id, group, version, plural, rtype, f"Karpenter resource {group}/{version}/{plural}"))

        return recs, fnds

    def _try_list_cr(self, env_tab: str, account_id: str, group: str, version: str, plural: str, rtype: str, desc: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        try:
            api = self.k8s_client.CustomObjectsApi()
            resp = api.list_cluster_custom_object(group=group, version=version, plural=plural)
            for obj in resp.get("items", []) or []:
                meta = obj.get("metadata", {}) or {}
                name = meta.get("name", "")
                out.append(record(
                    EnvTab=env_tab,
                    EnvByNameRule=sparta_name_rule(name),
                    Scope="Kubeconfig",
                    ResourceType=rtype,
                    Name=name,
                    Description=desc,
                    Id=f"{group}/{version}/{plural}/{name}",
                    AccountMasked=mask_account_id(account_id),
                    DetailsJson=json.dumps(obj, default=str),
                ))
        except Exception:
            return []
        return out


# =============================================================================
# Environment collection
# =============================================================================
@dataclass
class EnvironmentData:
    env_tab: str
    cluster_name: str
    region: str
    account_id: str
    records: List[Dict[str, Any]]
    findings: List[Dict[str, Any]]
    summary: Dict[str, Any]


def _role_name_from_arn(role_arn: str) -> str:
    return "" if not role_arn else role_arn.split("/")[-1]


def collect_iam_role(clients: AwsClients, env_tab: str, account_id: str, role_arn: str, scope: str) -> List[Dict[str, Any]]:
    """
    Collect IAM role metadata plus attached policy names/ARNs and inline policy names.
    (No policy documents to reduce leakage risk.)
    """
    if not role_arn:
        return []
    role_name = _role_name_from_arn(role_arn)
    recs: List[Dict[str, Any]] = []
    try:
        r = aws_call(clients.iam.get_role, RoleName=role_name)["Role"]
        tags = tags_list_to_dict(r.get("Tags", []))
        name = r.get("RoleName", role_name)
        env_by_rule = sparta_name_rule(name)
        if not should_include_resource(env_tab, env_by_rule):
            return []
        recs.append(record(
            EnvTab=env_tab,
            EnvByNameRule=env_by_rule,
            Scope=scope,
            ResourceType="IAMRole",
            Name=name,
            Description=r.get("Description", "") or "",
            Id=r.get("RoleId", ""),
            Arn=r.get("Arn", role_arn),
            Region=clients.ec2.meta.region_name or "",
            AccountMasked=mask_account_id(account_id),
            TagsJson=tags_to_json(tags),
            DetailsJson=json.dumps({"Path": r.get("Path"), "CreateDate": str(r.get("CreateDate")), "MaxSessionDuration": r.get("MaxSessionDuration")}, default=str),
        ))
        # Attached managed policies
        aps = paginate(clients.iam, "list_attached_role_policies", "AttachedPolicies", RoleName=role_name)
        for ap in aps:
            recs.append(record(
                EnvTab=env_tab,
                EnvByNameRule=sparta_name_rule(ap.get("PolicyName", "")),
                Scope=scope,
                ResourceType="IAMRoleManagedPolicyAttachment",
                Name=ap.get("PolicyName", ""),
                Description="Managed policy attached to role",
                Arn=ap.get("PolicyArn", ""),
                AccountMasked=mask_account_id(account_id),
                DetailsJson=json.dumps({"RoleArn": role_arn, "PolicyArn": ap.get("PolicyArn", "")}, default=str),
            ))
        # Inline policy names
        ips = paginate(clients.iam, "list_role_policies", "PolicyNames", RoleName=role_name)
        for ip in ips:
            recs.append(record(
                EnvTab=env_tab,
                EnvByNameRule=sparta_name_rule(ip),
                Scope=scope,
                ResourceType="IAMRoleInlinePolicy",
                Name=ip,
                Description="Inline policy name (document not exported)",
                AccountMasked=mask_account_id(account_id),
                DetailsJson=json.dumps({"RoleArn": role_arn, "InlinePolicyName": ip}, default=str),
            ))
    except ClientError as e:
        LOG.warning("IAM get_role failed for %s: %s", role_arn, e)
    return recs


def collect_environment(
    clients: AwsClients,
    env_tab: str,
    cluster_name: str,
    account_id: str,
    threshold: int,
    kube: Optional[KubeCollectors],
) -> EnvironmentData:
    records: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    region = clients.ec2.meta.region_name or ""

    # -------------------------
    # EKS cluster
    # -------------------------
    c = aws_call(clients.eks.describe_cluster, name=cluster_name)["cluster"]
    cluster_arn = c.get("arn", "")
    role_arn = c.get("roleArn", "")
    vpc_cfg = c.get("resourcesVpcConfig", {}) or {}
    vpc_id = vpc_cfg.get("vpcId", "")
    cluster_subnets = set(vpc_cfg.get("subnetIds", []) or [])

    # EKS tags
    eks_tags = {}
    try:
        eks_tags = aws_call(clients.eks.list_tags_for_resource, resourceArn=cluster_arn).get("tags", {}) or {}
    except ClientError:
        eks_tags = {}

    records.append(record(
        EnvTab=env_tab,
        EnvByNameRule=sparta_name_rule(cluster_name),
        Scope="Cluster",
        ResourceType="EKSCluster",
        Name=c.get("name", cluster_name),
        Description="Amazon EKS cluster",
        Arn=cluster_arn,
        Region=region,
        AccountMasked=mask_account_id(account_id),
        VpcId=vpc_id,
        SecurityGroupIds=",".join(vpc_cfg.get("securityGroupIds", []) or []),
        DetailsJson=json.dumps({
            "Status": c.get("status"),
            "Version": c.get("version"),
            "Endpoint": c.get("endpoint"),
            "RoleArn": role_arn,
            "SubnetIds": list(cluster_subnets),
            "ClusterSecurityGroupId": vpc_cfg.get("clusterSecurityGroupId"),
            "EndpointPublicAccess": vpc_cfg.get("endpointPublicAccess"),
            "EndpointPrivateAccess": vpc_cfg.get("endpointPrivateAccess"),
        }, default=str),
        TagsJson=json.dumps(eks_tags, sort_keys=True),
    ))

    # IAM cluster role
    records.extend(collect_iam_role(clients, env_tab, account_id, role_arn, "Cluster"))

    # -------------------------
    # EKS add-ons
    # -------------------------
    addons = paginate(clients.eks, "list_addons", "addons", clusterName=cluster_name)
    for an in addons:
        try:
            a = aws_call(clients.eks.describe_addon, clusterName=cluster_name, addonName=an)["addon"]
        except ClientError as e:
            LOG.warning("describe_addon failed for %s/%s: %s", cluster_name, an, e)
            continue
        records.append(record(
            EnvTab=env_tab,
            EnvByNameRule=sparta_name_rule(an),
            Scope="Cluster",
            ResourceType="EKSAddon",
            Name=a.get("addonName", an),
            Description="EKS add-on",
            Arn=a.get("addonArn", ""),
            Region=region,
            AccountMasked=mask_account_id(account_id),
            VpcId=vpc_id,
            DetailsJson=json.dumps({
                "AddonVersion": a.get("addonVersion"),
                "Status": a.get("status"),
                "ServiceAccountRoleArn": a.get("serviceAccountRoleArn"),
                "ConfigurationValues": a.get("configurationValues"),
            }, default=str),
        ))
        # Optional IAM role attached to add-on service account
        sa_role = a.get("serviceAccountRoleArn", "")
        if sa_role:
            records.extend(collect_iam_role(clients, env_tab, account_id, sa_role, "Cluster"))

    # -------------------------
    # EKS managed node groups
    # -------------------------
    nodegroups = paginate(clients.eks, "list_nodegroups", "nodegroups", clusterName=cluster_name)
    asg_names: List[str] = []
    node_role_arns: List[str] = []
    lt_ids: List[str] = []
    nodegroup_subnets: set[str] = set()

    for ng in nodegroups:
        try:
            ngd = aws_call(clients.eks.describe_nodegroup, clusterName=cluster_name, nodegroupName=ng)["nodegroup"]
        except ClientError as e:
            LOG.warning("describe_nodegroup failed for %s/%s: %s", cluster_name, ng, e)
            continue

        nodegroup_subnets |= set(ngd.get("subnets", []) or [])
        node_role = ngd.get("nodeRole", "")
        if node_role:
            node_role_arns.append(node_role)

        lt = ngd.get("launchTemplate") or {}
        if lt.get("id"):
            lt_ids.append(lt["id"])

        resources = ngd.get("resources", {}) or {}
        for g in resources.get("autoScalingGroups", []) or []:
            if isinstance(g, dict) and g.get("name"):
                asg_names.append(g["name"])

        records.append(record(
            EnvTab=env_tab,
            EnvByNameRule=sparta_name_rule(ng),
            Scope="Cluster",
            ResourceType="EKSManagedNodeGroup",
            Name=ngd.get("nodegroupName", ng),
            Description="EKS managed node group",
            Id=ngd.get("nodegroupName", ng),
            Arn=ngd.get("nodegroupArn", ""),
            Region=region,
            AccountMasked=mask_account_id(account_id),
            VpcId=vpc_id,
            DetailsJson=json.dumps({
                "Status": ngd.get("status"),
                "NodeRoleArn": node_role,
                "Subnets": ngd.get("subnets"),
                "InstanceTypes": ngd.get("instanceTypes"),
                "CapacityType": ngd.get("capacityType"),
                "ScalingConfig": ngd.get("scalingConfig"),
                "LaunchTemplate": lt,
                "Labels": ngd.get("labels"),
                "Taints": ngd.get("taints"),
                "Tags": ngd.get("tags"),
            }, default=str),
        ))

    # IAM roles for node groups
    for rn in sorted(set(node_role_arns)):
        records.extend(collect_iam_role(clients, env_tab, account_id, rn, "Cluster"))

    # -------------------------
    # Fargate profiles
    # -------------------------
    fps = paginate(clients.eks, "list_fargate_profiles", "fargateProfileNames", clusterName=cluster_name)
    fargate_subnets: set[str] = set()
    for fp in fps:
        try:
            fpd = aws_call(clients.eks.describe_fargate_profile, clusterName=cluster_name, fargateProfileName=fp)["fargateProfile"]
        except ClientError as e:
            LOG.warning("describe_fargate_profile failed for %s/%s: %s", cluster_name, fp, e)
            continue
        fargate_subnets |= set(fpd.get("subnets", []) or [])
        records.append(record(
            EnvTab=env_tab,
            EnvByNameRule=sparta_name_rule(fp),
            Scope="Cluster",
            ResourceType="EKSFargateProfile",
            Name=fpd.get("fargateProfileName", fp),
            Description="EKS Fargate profile",
            Id=fpd.get("fargateProfileName", fp),
            Arn=fpd.get("fargateProfileArn", ""),
            Region=region,
            AccountMasked=mask_account_id(account_id),
            VpcId=vpc_id,
            DetailsJson=json.dumps({
                "Status": fpd.get("status"),
                "Subnets": fpd.get("subnets"),
                "Selectors": fpd.get("selectors"),
                "PodExecutionRoleArn": fpd.get("podExecutionRoleArn"),
            }, default=str),
        ))
        per = fpd.get("podExecutionRoleArn", "")
        if per:
            records.extend(collect_iam_role(clients, env_tab, account_id, per, "Cluster"))

    # -------------------------
    # VPC + subnets + routing/security
    # -------------------------
    vpcs = aws_call(clients.ec2.describe_vpcs, VpcIds=[vpc_id]).get("Vpcs", [])
    v = vpcs[0] if vpcs else {}
    vtags = tags_list_to_dict(v.get("Tags", []))
    vname = get_name_tag(vtags) or vpc_id
    env_by_rule = sparta_name_rule(vname)
    if should_include_resource(env_tab, env_by_rule):
        records.append(record(
            EnvTab=env_tab,
            EnvByNameRule=env_by_rule,
            Scope="VPC",
            ResourceType="VPC",
            Name=vname,
            Description="VPC containing the cluster",
            Id=vpc_id,
            Region=region,
            AccountMasked=mask_account_id(account_id),
            VpcId=vpc_id,
            CidrBlock=v.get("CidrBlock", ""),
            TagsJson=tags_to_json(vtags),
            DetailsJson=json.dumps({
                "State": v.get("State"),
                "IsDefault": v.get("IsDefault"),
                "CidrBlockAssociationSet": v.get("CidrBlockAssociationSet"),
                "Ipv6CidrBlockAssociationSet": v.get("Ipv6CidrBlockAssociationSet"),
            }, default=str),
        ))

    # Subnets in VPC
    subnets = paginate(clients.ec2, "describe_subnets", "Subnets", Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    subnet_metrics_map: Dict[str, Dict[str, Any]] = {}

    for sn in subnets:
        sid = sn.get("SubnetId", "")
        cidr = sn.get("CidrBlock", "")
        avail = sn.get("AvailableIpAddressCount")
        met = subnet_ip_metrics(cidr, avail)
        subnet_metrics_map[sid] = met

        stags = tags_list_to_dict(sn.get("Tags", []))
        sname = get_name_tag(stags) or sid
        env_by_rule = sparta_name_rule(sname)

        if not should_include_resource(env_tab, env_by_rule):
            continue

        records.append(record(
            EnvTab=env_tab,
            EnvByNameRule=env_by_rule,
            Scope="VPC",
            ResourceType="Subnet",
            Name=sname,
            Description="Subnet in cluster VPC",
            Id=sid,
            Region=region,
            AccountMasked=mask_account_id(account_id),
            VpcId=vpc_id,
            SubnetId=sid,
            AvailabilityZone=sn.get("AvailabilityZone", ""),
            CidrBlock=cidr,
            TotalUsableIps=met["TotalUsableIps"],
            AvailableIps=met["AvailableIps"],
            UsedIps=met["UsedIps"],
            PctUsed=met["PctUsed"],
            TagsJson=tags_to_json(stags),
            DetailsJson=json.dumps({
                "State": sn.get("State"),
                "MapPublicIpOnLaunch": sn.get("MapPublicIpOnLaunch"),
                "IsClusterSubnet": sid in cluster_subnets,
                "IsNodegroupSubnet": sid in nodegroup_subnets,
                "IsFargateSubnet": sid in fargate_subnets,
            }, default=str),
        ))

        if met["AvailableIps"] is not None and met["AvailableIps"] <= threshold:
            findings.append(finding(
                FindingId=f"{env_tab}-low-free-ip-{sid}",
                EnvTab=env_tab,
                Severity="High" if met["AvailableIps"] <= max(8, threshold // 4) else "Medium",
                Category="SubnetFreeIPs",
                ResourceType="Subnet",
                ResourceId=sid,
                ResourceName=sname,
                Evidence=f"AvailableIps={met['AvailableIps']} threshold={threshold} PctUsed={met['PctUsed']}",
                Hypothesis="Node launches and/or Pod IP allocation can fail if targeted subnets are low on free IPs, even when the overall VPC CIDR appears large.",
                RecommendedChecks="Confirm nodegroup/ASG subnet targeting; check scaling activities for IP or /28 errors; consider larger/new subnets.",
            ))

    # Route tables, NACLs, security groups, NAT GWs, IGWs, VPC endpoints (VPC-scoped)
    def add_vpc_scoped(op: str, key: str, rtype: str, name_fn, desc_fn):
        items = paginate(clients.ec2, op, key, Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]) if op not in {"describe_internet_gateways"} else []
        return items

    # Route tables
    rts = paginate(clients.ec2, "describe_route_tables", "RouteTables", Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    for rt in rts:
        rid = rt.get("RouteTableId", "")
        t = tags_list_to_dict(rt.get("Tags", []))
        n = get_name_tag(t) or rid
        env_by_rule = sparta_name_rule(n)
        if not should_include_resource(env_tab, env_by_rule):
            continue
        records.append(record(
            EnvTab=env_tab, EnvByNameRule=env_by_rule, Scope="VPC", ResourceType="RouteTable",
            Name=n, Description="Route table in cluster VPC", Id=rid,
            Region=region, AccountMasked=mask_account_id(account_id), VpcId=vpc_id,
            RouteTableIds=rid, TagsJson=tags_to_json(t),
            DetailsJson=json.dumps({"RouteCount": len(rt.get("Routes", []) or []), "Associations": rt.get("Associations")}, default=str),
        ))

    # Network ACLs
    nacls = paginate(clients.ec2, "describe_network_acls", "NetworkAcls", Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    for na in nacls:
        nid = na.get("NetworkAclId", "")
        t = tags_list_to_dict(na.get("Tags", []))
        n = get_name_tag(t) or nid
        env_by_rule = sparta_name_rule(n)
        if not should_include_resource(env_tab, env_by_rule):
            continue
        records.append(record(
            EnvTab=env_tab, EnvByNameRule=env_by_rule, Scope="VPC", ResourceType="NetworkAcl",
            Name=n, Description="Network ACL in cluster VPC", Id=nid,
            Region=region, AccountMasked=mask_account_id(account_id), VpcId=vpc_id,
            NetworkAclIds=nid, TagsJson=tags_to_json(t),
            DetailsJson=json.dumps({"IsDefault": na.get("IsDefault"), "EntryCount": len(na.get("Entries", []) or [])}, default=str),
        ))

    # Security groups
    sgs = paginate(clients.ec2, "describe_security_groups", "SecurityGroups", Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    for sg in sgs:
        gid = sg.get("GroupId", "")
        gname = sg.get("GroupName", "") or gid
        gdesc = sg.get("Description", "") or ""
        t = tags_list_to_dict(sg.get("Tags", []))
        n = get_name_tag(t) or gname
        env_by_rule = sparta_name_rule(n)
        if not should_include_resource(env_tab, env_by_rule):
            continue
        records.append(record(
            EnvTab=env_tab, EnvByNameRule=env_by_rule, Scope="VPC", ResourceType="SecurityGroup",
            Name=n, Description=gdesc, Id=gid,
            Region=region, AccountMasked=mask_account_id(account_id), VpcId=vpc_id,
            SecurityGroupIds=gid, TagsJson=tags_to_json(t),
            DetailsJson=json.dumps({"GroupName": gname, "IngressRules": len(sg.get("IpPermissions", []) or []), "EgressRules": len(sg.get("IpPermissionsEgress", []) or [])}, default=str),
        ))

    # NAT gateways
    ngws = paginate(clients.ec2, "describe_nat_gateways", "NatGateways", Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    for ngw in ngws:
        nid = ngw.get("NatGatewayId", "")
        t = tags_list_to_dict(ngw.get("Tags", []))
        n = get_name_tag(t) or nid
        env_by_rule = sparta_name_rule(n)
        if not should_include_resource(env_tab, env_by_rule):
            continue
        records.append(record(
            EnvTab=env_tab, EnvByNameRule=env_by_rule, Scope="VPC", ResourceType="NatGateway",
            Name=n, Description="NAT gateway in cluster VPC", Id=nid,
            Region=region, AccountMasked=mask_account_id(account_id), VpcId=vpc_id,
            SubnetId=ngw.get("SubnetId", ""), NatGatewayIds=nid, TagsJson=tags_to_json(t),
            DetailsJson=json.dumps({"State": ngw.get("State"), "ConnectivityType": ngw.get("ConnectivityType"), "Addresses": ngw.get("NatGatewayAddresses")}, default=str),
        ))

    # Internet gateways (different filter shape)
    igws = paginate(clients.ec2, "describe_internet_gateways", "InternetGateways", Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}])
    for igw in igws:
        iid = igw.get("InternetGatewayId", "")
        t = tags_list_to_dict(igw.get("Tags", []))
        n = get_name_tag(t) or iid
        env_by_rule = sparta_name_rule(n)
        if not should_include_resource(env_tab, env_by_rule):
            continue
        records.append(record(
            EnvTab=env_tab, EnvByNameRule=env_by_rule, Scope="VPC", ResourceType="InternetGateway",
            Name=n, Description="Internet gateway attached to VPC", Id=iid,
            Region=region, AccountMasked=mask_account_id(account_id), VpcId=vpc_id,
            InternetGatewayIds=iid, TagsJson=tags_to_json(t),
            DetailsJson=json.dumps({"Attachments": igw.get("Attachments")}, default=str),
        ))

    # VPC endpoints
    vpes = paginate(clients.ec2, "describe_vpc_endpoints", "VpcEndpoints", Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    for vpe in vpes:
        vid = vpe.get("VpcEndpointId", "")
        t = tags_list_to_dict(vpe.get("Tags", []))
        n = get_name_tag(t) or vid
        env_by_rule = sparta_name_rule(n)
        if not should_include_resource(env_tab, env_by_rule):
            continue
        records.append(record(
            EnvTab=env_tab, EnvByNameRule=env_by_rule, Scope="VPC", ResourceType="VpcEndpoint",
            Name=n, Description="VPC endpoint", Id=vid,
            Region=region, AccountMasked=mask_account_id(account_id), VpcId=vpc_id,
            VpcEndpointIds=vid, SecurityGroupIds=",".join([g.get("GroupId", "") for g in (vpe.get("Groups") or []) if g.get("GroupId")]),
            TagsJson=tags_to_json(t),
            DetailsJson=json.dumps({"ServiceName": vpe.get("ServiceName"), "Type": vpe.get("VpcEndpointType"), "State": vpe.get("State"), "SubnetIds": vpe.get("SubnetIds"), "RouteTableIds": vpe.get("RouteTableIds")}, default=str),
        ))

    # -------------------------
    # ENIs in VPC (private IP counts / attachment counts)
    # -------------------------
    enis = paginate(clients.ec2, "describe_network_interfaces", "NetworkInterfaces", Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    eni_private_ips_by_subnet: Dict[str, int] = {}
    eni_count_by_subnet: Dict[str, int] = {}

    for eni in enis:
        eid = eni.get("NetworkInterfaceId", "")
        sid = eni.get("SubnetId", "")
        az = eni.get("AvailabilityZone", "")
        desc = eni.get("Description", "") or ""
        priv_ips = eni.get("PrivateIpAddresses", []) or []
        priv_count = len(priv_ips)
        sec_count = max(priv_count - 1, 0)
        att = eni.get("Attachment") or {}
        inst_id = att.get("InstanceId", "") or ""

        t = tags_list_to_dict(eni.get("TagSet", []) or eni.get("Tags", []) or [])
        n = get_name_tag(t) or eid
        env_by_rule = sparta_name_rule(n)
        if not should_include_resource(env_tab, env_by_rule):
            continue

        eni_private_ips_by_subnet[sid] = eni_private_ips_by_subnet.get(sid, 0) + priv_count
        eni_count_by_subnet[sid] = eni_count_by_subnet.get(sid, 0) + 1

        records.append(record(
            EnvTab=env_tab, EnvByNameRule=env_by_rule, Scope="VPC", ResourceType="ENI",
            Name=n, Description=desc, Id=eid,
            Region=region, AccountMasked=mask_account_id(account_id), VpcId=vpc_id,
            SubnetId=sid, AvailabilityZone=az,
            EniId=eid, EniAttachmentInstanceId=inst_id,
            EniPrivateIpCount=priv_count, EniSecondaryIpCount=sec_count,
            SecurityGroupIds=",".join([g.get("GroupId", "") for g in (eni.get("Groups") or []) if g.get("GroupId")]),
            TagsJson=tags_to_json(t),
            DetailsJson=json.dumps({"InterfaceType": eni.get("InterfaceType"), "RequesterManaged": eni.get("RequesterManaged"), "Attachment": att, "Ipv4Prefixes": eni.get("Ipv4Prefixes")}, default=str),
        ))

        # Evidence for SG for Pods trunk/branch pattern (useful when optional kubeconfig isn't used)
        if "aws-k8s-trunk-eni" in desc or "aws-k8s-branch-eni" in desc:
            findings.append(finding(
                FindingId=f"{env_tab}-pod-eni-detected-{eid}",
                EnvTab=env_tab,
                Severity="Info",
                Category="SecurityGroupsForPods",
                ResourceType="ENI",
                ResourceId=eid,
                ResourceName=n,
                Evidence=f"ENI Description matches trunk/branch pattern: {desc}",
                Hypothesis="Security Groups for Pods (trunk/branch ENIs) may be enabled, altering ENI/IP consumption.",
                RecommendedChecks="Use --kubeconfig to confirm ENABLE_POD_ENI; ensure VPC resource controller policy is attached to cluster role.",
            ))

    # ENI pressure findings (subnet-level)
    for sid, met in subnet_metrics_map.items():
        if met.get("AvailableIps") is None or met.get("TotalUsableIps") is None:
            continue
        if met["AvailableIps"] <= threshold:
            findings.append(finding(
                FindingId=f"{env_tab}-subnet-eni-pressure-{sid}",
                EnvTab=env_tab,
                Severity="Medium",
                Category="SubnetENIConsumption",
                ResourceType="Subnet",
                ResourceId=sid,
                ResourceName=sid,
                Evidence=f"ENIs={eni_count_by_subnet.get(sid,0)} ENI-private-IPs={eni_private_ips_by_subnet.get(sid,0)} AvailableIps={met['AvailableIps']} PctUsed={met['PctUsed']}",
                Hypothesis="Subnet is low on free IPs and has significant ENI/private-IP consumption; new nodes or pods may fail to allocate.",
                RecommendedChecks="Correlate ENI owners by tags/attachment instance IDs; validate VPC CNI warm pool settings and prefix delegation.",
            ))

    # -------------------------
    # Auto Scaling groups + scaling activities
    # -------------------------
    asg_names = sorted(set(asg_names))
    instance_ids: List[str] = []
    for batch in chunked(asg_names, 50):
        try:
            gs = aws_call(clients.autoscaling.describe_auto_scaling_groups, AutoScalingGroupNames=list(batch), IncludeInstances=True).get("AutoScalingGroups", []) or []
        except ClientError as e:
            LOG.warning("describe_auto_scaling_groups failed: %s", e)
            continue
        for g in gs:
            gname = g.get("AutoScalingGroupName", "")
            garn = g.get("AutoScalingGroupARN", "")
            records.append(record(
                EnvTab=env_tab, EnvByNameRule=sparta_name_rule(gname), Scope="Cluster", ResourceType="AutoScalingGroup",
                Name=gname, Description="ASG backing EKS node groups", Id=gname, Arn=garn,
                Region=region, AccountMasked=mask_account_id(account_id), VpcId=vpc_id,
                AutoScalingGroupName=gname,
                DetailsJson=json.dumps({
                    "MinSize": g.get("MinSize"),
                    "MaxSize": g.get("MaxSize"),
                    "DesiredCapacity": g.get("DesiredCapacity"),
                    "VPCZoneIdentifier": g.get("VPCZoneIdentifier"),
                    "LaunchTemplate": g.get("LaunchTemplate"),
                    "MixedInstancesPolicy": g.get("MixedInstancesPolicy"),
                    "Tags": g.get("Tags"),
                }, default=str),
            ))

            # scaling activities: capture failed/cancelled and include evidence
            try:
                acts = aws_call(clients.autoscaling.describe_scaling_activities, AutoScalingGroupName=gname, MaxRecords=20).get("Activities", []) or []
            except ClientError:
                acts = []
            for a in acts:
                sc = a.get("StatusCode", "")
                msg = a.get("StatusMessage", "") or ""
                if sc in {"Failed", "Cancelled"} or "InsufficientFreeAddressesInSubnet" in msg or "InsufficientCidrBlocks" in msg:
                    findings.append(finding(
                        FindingId=f"{env_tab}-asg-activity-{gname}-{a.get('ActivityId','')}",
                        EnvTab=env_tab,
                        Severity="High",
                        Category="NodeLaunchFailure",
                        ResourceType="AutoScalingGroup",
                        ResourceId=gname,
                        ResourceName=gname,
                        Evidence=f"StatusCode={sc}; StatusMessage={msg}",
                        Hypothesis="ASG failed to launch nodes; message often pinpoints subnet free-IP exhaustion, /28 contiguity errors, or other capacity constraints.",
                        RecommendedChecks="Correlate with low-free-IP subnets; if /28 errors, review prefix delegation fragmentation and CIDR reservations; validate warm pool configuration.",
                    ))

            for inst in g.get("Instances", []) or []:
                iid = inst.get("InstanceId")
                if iid:
                    instance_ids.append(iid)

    instance_ids = sorted(set(instance_ids))

    # -------------------------
    # EC2 instances + instance type ENI/IP limits
    # -------------------------
    instances: List[Dict[str, Any]] = []
    for batch in chunked(instance_ids, 200):
        try:
            resp = aws_call(clients.ec2.describe_instances, InstanceIds=list(batch))
        except ClientError as e:
            LOG.warning("describe_instances failed: %s", e)
            continue
        for r in resp.get("Reservations", []) or []:
            instances.extend(r.get("Instances", []) or [])

    itypes = sorted({i.get("InstanceType") for i in instances if i.get("InstanceType")})
    itype_limits: Dict[str, Dict[str, Any]] = {}
    for batch in chunked(itypes, 100):
        try:
            its = aws_call(clients.ec2.describe_instance_types, InstanceTypes=list(batch)).get("InstanceTypes", []) or []
        except ClientError as e:
            LOG.warning("describe_instance_types failed: %s", e)
            continue
        for it in its:
            ni = it.get("NetworkInfo", {}) or {}
            itype_limits[it.get("InstanceType", "")] = {
                "MaxENIs": ni.get("MaximumNetworkInterfaces"),
                "Ipv4PerENI": ni.get("Ipv4AddressesPerInterface"),
            }

    for inst in instances:
        iid = inst.get("InstanceId", "")
        it = inst.get("InstanceType", "")
        state = (inst.get("State") or {}).get("Name", "")
        sid = inst.get("SubnetId", "")
        az = (inst.get("Placement") or {}).get("AvailabilityZone", "")
        t = tags_list_to_dict(inst.get("Tags", []))
        name = get_name_tag(t) or iid
        env_by_rule = sparta_name_rule(name)
        if not should_include_resource(env_tab, env_by_rule):
            continue

        enis_att = inst.get("NetworkInterfaces", []) or []
        eni_count = len(enis_att)

        lim = itype_limits.get(it, {})
        max_enis = lim.get("MaxENIs")
        ipv4_per = lim.get("Ipv4PerENI")
        max_pods = None
        if isinstance(max_enis, int) and isinstance(ipv4_per, int) and ipv4_per > 0:
            # EKS best-practices formula: (ENIs*(IPs per ENI - 1)) + 2
            max_pods = (max_enis * (ipv4_per - 1)) + 2

        records.append(record(
            EnvTab=env_tab, EnvByNameRule=env_by_rule, Scope="Cluster", ResourceType="EC2Instance",
            Name=name, Description="EC2 instance from ASG(s) (likely node)", Id=iid,
            Region=region, AccountMasked=mask_account_id(account_id), VpcId=vpc_id,
            SubnetId=sid, AvailabilityZone=az,
            InstanceId=iid, InstanceType=it, InstanceState=state,
            EniCountAttachedToInstance=eni_count,
            SecurityGroupIds=",".join([sg.get("GroupId", "") for sg in (inst.get("SecurityGroups") or []) if sg.get("GroupId")]),
            TagsJson=tags_to_json(t),
            DetailsJson=json.dumps({
                "PrivateIpAddress": inst.get("PrivateIpAddress"),
                "MaxENIs": max_enis,
                "Ipv4AddressesPerInterface": ipv4_per,
                "MaxPodsTheoretical": max_pods,
            }, default=str),
        ))

        if isinstance(max_enis, int) and max_enis > 0 and eni_count >= max_enis:
            findings.append(finding(
                FindingId=f"{env_tab}-eni-limit-{iid}",
                EnvTab=env_tab,
                Severity="Medium",
                Category="InstanceENILimit",
                ResourceType="EC2Instance",
                ResourceId=iid,
                ResourceName=name,
                Evidence=f"AttachedENIs={eni_count} >= MaxENIs({it})={max_enis}",
                Hypothesis="Node may be at ENI attachment ceiling, limiting additional IP allocations for pods; can look like IP exhaustion.",
                RecommendedChecks="Right-size instance type, review max-pods, evaluate prefix delegation or warm pool changes.",
            ))

    # -------------------------
    # Launch templates referenced by nodegroups and/or ASGs (metadata only)
    # -------------------------
    # add ASG launch templates
    for batch in chunked(asg_names, 50):
        try:
            gs = aws_call(clients.autoscaling.describe_auto_scaling_groups, AutoScalingGroupNames=list(batch), IncludeInstances=False).get("AutoScalingGroups", []) or []
        except ClientError:
            gs = []
        for g in gs:
            lt = g.get("LaunchTemplate") or {}
            if lt.get("LaunchTemplateId"):
                lt_ids.append(lt["LaunchTemplateId"])

    lt_ids = sorted(set([x for x in lt_ids if x]))
    for batch in chunked(lt_ids, 200):
        try:
            lts = aws_call(clients.ec2.describe_launch_templates, LaunchTemplateIds=list(batch)).get("LaunchTemplates", []) or []
        except ClientError as e:
            LOG.warning("describe_launch_templates failed: %s", e)
            continue
        for lt in lts:
            lid = lt.get("LaunchTemplateId", "")
            lname = lt.get("LaunchTemplateName", lid)
            env_by_rule = sparta_name_rule(lname)
            if not should_include_resource(env_tab, env_by_rule):
                continue
            records.append(record(
                EnvTab=env_tab, EnvByNameRule=env_by_rule, Scope="Cluster", ResourceType="LaunchTemplate",
                Name=lname, Description="Launch template metadata (no user-data exported)", Id=lid, Arn=lt.get("LaunchTemplateArn", ""),
                Region=region, AccountMasked=mask_account_id(account_id), VpcId=vpc_id,
                DetailsJson=json.dumps({
                    "DefaultVersionNumber": lt.get("DefaultVersionNumber"),
                    "LatestVersionNumber": lt.get("LatestVersionNumber"),
                    "CreatedBy": lt.get("CreatedBy"),
                    "CreateTime": str(lt.get("CreateTime")),
                }, default=str),
            ))

    # -------------------------
    # Optional kubeconfig augmentation
    # -------------------------
    if kube is not None:
        k_recs, k_fnds = kube.collect(env_tab=env_tab, account_id=account_id)
        records.extend(k_recs)
        findings.extend(k_fnds)

    summary = {
        "EnvTab": env_tab,
        "ClusterName": cluster_name,
        "VpcId": vpc_id,
        "RecordCount": len(records),
        "FindingCount": len(findings),
        "CollectedAtUtc": iso_utc_now(),
        "Threshold": threshold,
    }
    return EnvironmentData(env_tab, cluster_name, region, account_id, records, findings, summary)


# =============================================================================
# Deltas + Findings sheet builders
# =============================================================================
def build_deltas(et: EnvironmentData, stg: EnvironmentData) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []

    # Summary deltas
    keys = sorted(set(et.summary.keys()) | set(stg.summary.keys()))
    for k in keys:
        if et.summary.get(k) != stg.summary.get(k):
            rows.append({
                "Domain": "Summary",
                "Key": k,
                "ResourceType": "SummaryMetric",
                "Field": k,
                "SpartaET": str(et.summary.get(k)),
                "Sparta-Staging": str(stg.summary.get(k)),
                "DeltaSummary": f"{k}: ET={et.summary.get(k)} vs STG={stg.summary.get(k)}",
            })

    # Addon version diff
    def addon_versions(env: EnvironmentData) -> Dict[str, str]:
        out = {}
        for r in env.records:
            if r.get("ResourceType") == "EKSAddon":
                d = json.loads(r.get("DetailsJson") or "{}")
                out[r.get("Name") or ""] = str(d.get("AddonVersion") or "")
        return out

    a1 = addon_versions(et)
    a2 = addon_versions(stg)
    for an in sorted(set(a1.keys()) | set(a2.keys())):
        if a1.get(an) != a2.get(an):
            rows.append({
                "Domain": "EKSAddon",
                "Key": an,
                "ResourceType": "EKSAddon",
                "Field": "AddonVersion",
                "SpartaET": a1.get(an, ""),
                "Sparta-Staging": a2.get(an, ""),
                "DeltaSummary": "Add-on version differs",
            })

    # Subnet utilization deltas keyed by AZ|CIDR
    def subnet_map(env: EnvironmentData) -> Dict[str, Dict[str, Any]]:
        m = {}
        for r in env.records:
            if r.get("ResourceType") == "Subnet":
                key = f"{r.get('AvailabilityZone','')}|{r.get('CidrBlock','')}"
                m[key] = r
        return m

    s1 = subnet_map(et)
    s2 = subnet_map(stg)
    for key in sorted(set(s1.keys()) | set(s2.keys())):
        r1 = s1.get(key)
        r2 = s2.get(key)
        if not r1 or not r2:
            rows.append({
                "Domain": "Subnet",
                "Key": key,
                "ResourceType": "Subnet",
                "Field": "Presence",
                "SpartaET": "Present" if r1 else "Missing",
                "Sparta-Staging": "Present" if r2 else "Missing",
                "DeltaSummary": "Subnet set differs (keyed by AZ|CIDR).",
            })
            continue
        if r1.get("AvailableIps") != r2.get("AvailableIps") or r1.get("PctUsed") != r2.get("PctUsed"):
            rows.append({
                "Domain": "Subnet",
                "Key": key,
                "ResourceType": "Subnet",
                "Field": "AvailableIps/PctUsed",
                "SpartaET": f"Avail={r1.get('AvailableIps')} Pct={r1.get('PctUsed')}",
                "Sparta-Staging": f"Avail={r2.get('AvailableIps')} Pct={r2.get('PctUsed')}",
                "DeltaSummary": "Subnet utilization differs; check which ASGs target these subnets.",
            })

    return pd.DataFrame(rows, columns=DELTA_COLUMNS)


def build_findings(et: EnvironmentData, stg: EnvironmentData) -> pd.DataFrame:
    all_f = et.findings + stg.findings
    return pd.DataFrame(all_f, columns=FINDING_COLUMNS)


# =============================================================================
# Excel writer (filters + freeze panes)
# =============================================================================
def choose_engine() -> str:
    try:
        import xlsxwriter  # noqa: F401
        return "xlsxwriter"
    except Exception:
        return "openpyxl"


def write_sheet(writer: pd.ExcelWriter, sheet: str, header_lines: List[str], df: pd.DataFrame, startrow: int) -> None:
    df.to_excel(writer, sheet_name=sheet, index=False, startrow=startrow)

    if writer.engine != "xlsxwriter":
        return
    wb = writer.book
    ws = writer.sheets[sheet]
    bold = wb.add_format({"bold": True})
    wrap = wb.add_format({"text_wrap": True})

    for i, line in enumerate(header_lines):
        ws.write(i, 0, line, bold if i == 0 else None)

    header_row = startrow
    rows, cols = df.shape
    if cols > 0:
        ws.freeze_panes(header_row + 1, 0)
        ws.autofilter(header_row, 0, header_row + max(rows, 1), cols - 1)

        for c, name in enumerate(df.columns):
            width = max(12, min(52, len(name) + 2))
            if name.endswith("Json"):
                ws.set_column(c, c, 52, wrap)
            else:
                ws.set_column(c, c, width)


def write_workbook(output: str, et: EnvironmentData, stg: EnvironmentData, deltas: pd.DataFrame, findings: pd.DataFrame, threshold: int) -> None:
    engine = choose_engine()
    with pd.ExcelWriter(output, engine=engine) as writer:
        et_df = pd.DataFrame(et.records, columns=INVENTORY_COLUMNS)
        stg_df = pd.DataFrame(stg.records, columns=INVENTORY_COLUMNS)

        write_sheet(
            writer,
            "SpartaET",
            [
                "SpartaET Inventory",
                f"ClusterName: {et.cluster_name}",
                f"CollectedAtUtc: {et.summary['CollectedAtUtc']}",
                f"Threshold (AvailableIps): {threshold}",
                f"Account: {mask_account_id(et.account_id)}  Region: {et.region}",
            ],
            et_df,
            startrow=7,
        )

        write_sheet(
            writer,
            "Sparta-Staging",
            [
                "Sparta-Staging Inventory",
                f"ClusterName: {stg.cluster_name}",
                f"CollectedAtUtc: {stg.summary['CollectedAtUtc']}",
                f"Threshold (AvailableIps): {threshold}",
                f"Account: {mask_account_id(stg.account_id)}  Region: {stg.region}",
            ],
            stg_df,
            startrow=7,
        )

        write_sheet(
            writer,
            "Deltas",
            [
                "Deltas (SpartaET vs Sparta-Staging)",
                f"GeneratedAtUtc: {iso_utc_now()}",
                f"SpartaET Cluster: {et.cluster_name}",
                f"Sparta-Staging Cluster: {stg.cluster_name}",
            ],
            deltas,
            startrow=6,
        )

        exec_lines = [
            "Executive Summary and Findings",
            f"GeneratedAtUtc: {iso_utc_now()}",
            f"Account: {mask_account_id(et.account_id)}  Region: {et.region}",
            "",
            "High-signal IP exhaustion hypotheses supported here:",
            " - Subnets below free-IP threshold (AvailableIpAddressCount)",
            " - ENI/private-IP pressure per subnet (ENI counts, private IP totals)",
            " - ASG scaling activity failures (StatusMessage evidence)",
            " - Instance ENI ceilings (DescribeInstanceTypes limits + attached ENIs)",
            " - Optional kubeconfig: aws-node env vars, amazon-vpc-cni config, ENIConfigs, Karpenter CRs",
            "",
            f"SpartaET: Records={et.summary['RecordCount']} Findings={et.summary['FindingCount']}",
            f"Sparta-Staging: Records={stg.summary['RecordCount']} Findings={stg.summary['FindingCount']}",
        ]
        write_sheet(writer, "Findings", exec_lines, findings, startrow=16)


# =============================================================================
# Dry-run terminal output
# =============================================================================
def print_dry_run(account_id: str, et: EnvironmentData, stg: EnvironmentData, deltas: pd.DataFrame, findings: pd.DataFrame) -> None:
    print("\n=== DRY RUN (sanitized) ===")
    print(f"GeneratedAtUtc: {iso_utc_now()}")
    print(f"Account: {mask_account_id(account_id)}  Region: {sanitize_text(et.region, account_id)}\n")

    def counts(env: EnvironmentData) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for r in env.records:
            rt = r.get("ResourceType", "Unknown")
            out[rt] = out.get(rt, 0) + 1
        return dict(sorted(out.items(), key=lambda x: (-x[1], x[0])))

    print(f"SpartaET cluster: {sanitize_text(et.cluster_name, account_id)}  records={et.summary['RecordCount']}  findings={et.summary['FindingCount']}")
    print(f"Sparta-Staging cluster: {sanitize_text(stg.cluster_name, account_id)}  records={stg.summary['RecordCount']}  findings={stg.summary['FindingCount']}\n")

    print("Resource type counts (SpartaET):")
    for k, v in list(counts(et).items())[:20]:
        print(f"  - {k}: {v}")
    print("\nResource type counts (Sparta-Staging):")
    for k, v in list(counts(stg).items())[:20]:
        print(f"  - {k}: {v}")

    print(f"\nDeltas rows: {len(deltas)}")
    print(f"Findings rows: {len(findings)}\n")

    if not findings.empty:
        print("Top findings (first 15):")
        for f in findings.head(15).to_dict(orient="records"):
            msg = f"[{f.get('Severity')}] {f.get('EnvTab')} {f.get('Category')} {f.get('ResourceType')} {f.get('ResourceId')} :: {f.get('Evidence')}"
            print("  - " + sanitize_text(msg, account_id))

    print("\nSheets that would be written:")
    print("  - SpartaET")
    print("  - Sparta-Staging")
    print("  - Deltas")
    print("  - Findings")
    print("\nInventory schema columns:")
    print("  " + ", ".join(INVENTORY_COLUMNS))
    print("")


# =============================================================================
# CLI / main
# =============================================================================
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Inventory two EKS environments; output Excel with environment tabs, deltas, and findings.")
    p.add_argument("--dry-run", action="store_true", help="Collect and print sanitized summary; do not write Excel.")
    p.add_argument("--output", default="eks_two_env_inventory.xlsx", help="Output .xlsx file path.")
    p.add_argument("--threshold", type=int, default=DEFAULT_LOW_FREE_IP_THRESHOLD, help="Flag subnets with AvailableIps <= threshold.")
    p.add_argument("--kubeconfig", default="", help="Optional kubeconfig path to enable Kubernetes read-only augmentation.")
    p.add_argument("--kubecontext", default="", help="Optional kubecontext name.")
    return p.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    # Enforce user editing of placeholders
    if not CLUSTER_NAME_SPARTA_ET or not CLUSTER_NAME_SPARTA_STAGING:
        LOG.error("Cluster names are blank placeholders. Edit CLUSTER_NAME_SPARTA_ET and CLUSTER_NAME_SPARTA_STAGING near the top of the script.")
        return 2

    try:
        clients = build_clients()
    except Exception as e:
        LOG.error("Failed to initialize AWS clients. Ensure region is configured via AWS_REGION/AWS_DEFAULT_REGION or ~/.aws/config. Error=%s", e)
        return 2

    # Identify active account (used only for masking + workbook metadata)
    try:
        ident = aws_call(clients.sts.get_caller_identity)
        account_id = ident.get("Account", "")
        if not account_id:
            raise RuntimeError("sts:GetCallerIdentity returned empty Account")
    except Exception as e:
        LOG.error("Unable to call sts:GetCallerIdentity. Check local credentials. Error=%s", e)
        return 2

    kube = None
    if args.kubeconfig:
        try:
            kube = KubeCollectors(args.kubeconfig, args.kubecontext)
        except Exception as e:
            LOG.error("Failed to enable kubeconfig mode. Install 'kubernetes' package and verify kubeconfig/context. Error=%s", e)
            return 2

    try:
        et = collect_environment(clients, "SpartaET", CLUSTER_NAME_SPARTA_ET, account_id, args.threshold, kube)
        stg = collect_environment(clients, "Sparta-Staging", CLUSTER_NAME_SPARTA_STAGING, account_id, args.threshold, kube)
    except (ClientError, BotoCoreError) as e:
        LOG.error("AWS API error during collection: %s", e)
        return 1
    except Exception as e:
        LOG.error("Unexpected error during collection: %s", e)
        return 1

    deltas = build_deltas(et, stg)
    fdf = build_findings(et, stg)

    # Dry-run: print only, do not write Excel
    if args.dry_run:
        print_dry_run(account_id, et, stg, deltas, fdf)
        LOG.info("Dry-run complete. No files written.")
        return 0

    # Write workbook
    try:
        write_workbook(args.output, et, stg, deltas, fdf, args.threshold)
    except Exception as e:
        LOG.error("Failed to write workbook: %s", e)
        return 1

    # Print a small sanitized report even on success
    print_dry_run(account_id, et, stg, deltas, fdf)
    LOG.info("Workbook written: %s", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
