import subprocess
from pathlib import Path

OUTPUT_NAME = "eks-patching-incident"
MD_FILE = f"{OUTPUT_NAME}.md"
DOCX_FILE = f"{OUTPUT_NAME}.docx"

CONTENT = r"""# SpartaET EKS Patching Incident

**Patching Event Date:** March 10, 2026

---

## Summary

During patching, SpartaET did not recover as expected after nodes were cordoned and drained. Replacement nodes were unable to come online successfully, preventing workloads from being rescheduled.

### Impacted Environment

- Sparta-ET

### Not Impacted

- Sparta
- Sparta-Staging

---

## Environment Snapshot

- Sparta-Staging: ~40 pods / 4 nodes
- Sparta-ET: 500+ pods / 33 nodes
- Sparta: 422 pods / 19 nodes

---

## Infrastructure Layout

- Single AWS account
- Two VPCs:
  - sparta-live
  - sparta-et-live (shared by Sparta-ET and Sparta-Staging)

### SpartaET Details

- 10 subnets
- 3 AZs: 1a, 1b, 1c (1c includes sandbox)
- Subnets appear small (≈32 IPs observed per subnet)
- Sparta-Staging resources exist in subnets suffixed with “-dev”

---

## Working Hypothesis (Subject to Validation)

At this stage, the issue appears related to network capacity constraints that became visible during patching, rather than a direct compute limitation.

### In EKS:

- Each pod is assigned a real VPC IP via the AWS VPC CNI
- Nodes receive IPs through ENIs attached to the instance

### Because of this:

- Pod density is directly tied to available IP space
- Node scaling is constrained by subnet capacity and ENI limits
- Importantly, the CNI maintains a pool of pre-allocated (“warm”) IPs to speed up pod scheduling, which can consume IP space even when not actively in use

---

## Simplified View of EKS Networking (For Context)

To help frame the behavior, this can be viewed in simpler terms:

- Nodes act like buildings
- Pods are tenants
- IP addresses are mailing addresses
- ENIs are groups of mailboxes attached to each building
- The VPC CIDR is the total address space

### Each node has limits:

- A maximum number of ENIs
- A maximum number of IPs per ENI

Even if compute resources are available:

- Workloads cannot be scheduled without available IP capacity

This aligns with how EKS networking works, where each pod receives an IP from the VPC network itself

---

## Patching Behavior and Contributing Factors

### During patching:

- Nodes were drained → pods required rescheduling
- New nodes needed to be provisioned
- IP demand increased across the cluster in a short window

### At the same time:

- IP allocation depends on subnet availability and ENI limits
- ENI attachment and IP allocation are not instantaneous
- Pre-allocated IP pools may already be consuming available space

### Additional Complication Observed

- Kyverno policies interfered with node deletion
- Node lifecycle operations did not complete cleanly

This created a situation where:

- Nodes were attempting to terminate
- Policies were preventing termination
- Cluster state became inconsistent during scaling

Additionally:

- Sparta-Staging was fully scaled down in an attempt to free capacity
- This did not resolve the issue

### Operational flow context:

- Sparta-Staging → Sparta-ET → Sparta

---

## Why This May Be Isolated to SpartaET

Several differences likely contributed:

- Shared VPC (Sparta-ET + Sparta-Staging) increases contention potential
- Smaller subnet sizes reduce available headroom
- Higher pod density increases IP consumption
- Possible configuration differences (CNI settings, instance types, scaling patterns)

These conditions may not surface during steady-state operation, but become more visible during events that require rapid scaling or redistribution of workloads

---

## Observations

- SpartaET has the highest pod-to-node density
- Subnet capacity appears constrained relative to demand
- Total subnet count does not necessarily translate to usable capacity if each is small
- Shared VPC introduces potential fragmentation and uneven IP utilization

This type of configuration can operate normally under steady load, but may become constrained during operations like patching that temporarily increase demand

---

## Proposed Solutions

### Low Cost / Immediate

- Validate subnet IP availability prior to patching
- Improve visibility into ENI and IP allocation (CloudWatch, metrics)
- Temporarily relax Kyverno policies during controlled patch windows
- Ensure node groups are distributed evenly across subnets and AZs
- Review and tune CNI settings (WARM_IP_TARGET, MINIMUM_IP_TARGET)

---

### Medium Effort

- Enable prefix delegation to increase IP density per ENI
- Introduce secondary CIDR blocks for pod networking
- Enable enhanced subnet discovery to utilize all available subnets

---

### Higher Cost / Strategic

- Redesign subnet sizing to increase available IP space
- Separate Sparta-ET from shared VPC to reduce contention
- Evaluate IPv6 adoption for long-term scalability
- Consider custom networking to separate node and pod CIDR ranges

---

## Questions to Answer Next

- What was the actual available IP count per subnet during patching?
- Were failures tied more to subnet exhaustion or ENI limits?
- Are CNI configurations consistent across environments?
- Is prefix delegation enabled or configured differently?
- Is IP fragmentation occurring across subnets?

---

## Closing Perspective

This appears to be the result of multiple constraints interacting during a high-change operation.

The patching process did not introduce a new issue, but rather exposed limitations in how network capacity is currently allocated and consumed

---

## References & Supporting Material

- AWS EKS Best Practices – IP Optimization  
  https://docs.aws.amazon.com/eks/latest/best-practices/ip-opt.html  

- AWS VPC CNI Behavior and ENI Allocation  
  https://docs.aws.amazon.com/eks/latest/best-practices/vpc-cni.html  

- EKS Networking Explained  
  https://dev.to/dap0am_/eks-networking-explained-why-am-i-running-out-of-ips-part-1-8f3
"""

# WRITE MARKDOWN
Path(MD_FILE).write_text(CONTENT)
print(f"Created {MD_FILE}")

# CONVERT TO DOCX USING PANDOC
cmd = [
    "pandoc",
    "-f", "gfm",
    MD_FILE,
    "-o", DOCX_FILE,
    "--standalone"
]

result = subprocess.run(cmd)

if result.returncode == 0:
    print(f"Created {DOCX_FILE}")
else:
    print("Pandoc conversion failed. Make sure pandoc is installed.")
