# CSPM Policy Report Generator

Scripts to retrieve and export CrowdStrike CSPM (Cloud Security Posture Management) policy details via the Falcon API. Generates four separate CSV reports covering **IOMs** (cloud misconfigurations), **IOAs** (behavioral detections), **IAC rules** (infrastructure-as-code / container / API security), and **Cloud Risks** (toxic combinations).

## Overview

This tool generates comprehensive CSV reports of all CSPM policies in your CrowdStrike environment:

- **IOM Report** — Indicators of Misconfiguration (default and custom cloud configuration policies)
- **IOA Report** — Indicators of Attack (behavioral detection policies with MITRE ATT&CK-aligned attack types)
- **IAC Report** — Infrastructure-as-Code rules (Kubernetes, Docker, Helm, OpenAPI/Swagger, ASPM, and other non-cloud-native policies)
- **Cloud Risks Report** — Cloud security risks / toxic combinations (deduplicated rules with finding counts)

## Quick Start

```bash
# Set your credentials
export FALCON_CLIENT_ID="your_client_id_here"
export FALCON_CLIENT_SECRET="your_client_secret_here"

# Python (recommended — ~9s with concurrent requests)
python3 get-cspm-rules.py

# Bash (alternative — ~2.5 min, sequential)
bash get-cspm-rules.sh
```

### One-liner (no clone required)

```bash
curl -s https://raw.githubusercontent.com/kuhnskc/cspm-policy-report/main/get-cspm-rules.py | python3
```

## Prerequisites

### Python version (recommended)
- **python3** (3.7+) — no external dependencies, uses only the standard library

### Bash version
- **curl** — for API calls
- **jq** — for JSON processing
- **python3** — for policy classification and summary statistics

## Installation

```bash
git clone https://github.com/kuhnskc/cspm-policy-report.git
cd cspm-policy-report
```

## Setup

1. Set your Falcon API credentials as environment variables:
```bash
export FALCON_CLIENT_ID="your_client_id_here"
export FALCON_CLIENT_SECRET="your_client_secret_here"
```

2. Optionally set a custom base URL (defaults to `https://api.crowdstrike.com`):
```bash
export FALCON_BASE_URL="https://api.us-2.crowdstrike.com"
```

## Usage

```bash
# Python (recommended)
python3 get-cspm-rules.py

# Bash
bash get-cspm-rules.sh
```

Both scripts will:
1. Authenticate with the Falcon API
2. Fetch `settings/entities/policy/v1` to get IOA (Behavioral) policies and build a Configuration policy name list for classification
3. Retrieve all cloud-policy IDs via `cloud-policies/queries/rules/v1` (with pagination)
4. Fetch detailed cloud-policy information in batches via `cloud-policies/entities/rules/v1`
5. Classify each cloud-policy as **IOM** (exists in settings Configuration) or **IAC** (does not)
6. Fetch cloud risks via `cloud-security-risks/combined/cloud-risks/v1` and deduplicate by rule
7. Generate four timestamped CSV files and display summary statistics

### Output Files

| File | Contents | 
|---|---|
| `cspm_iom_report_TIMESTAMP.csv` | Cloud misconfigurations (AWS, Azure, GCP, OCI)
| `cspm_ioa_report_TIMESTAMP.csv` | Behavioral detections (AWS, Azure) 
| `cspm_iac_report_TIMESTAMP.csv` | IAC / container / API security rules
| `cspm_cloud_risks_report_TIMESTAMP.csv` | Cloud risks / toxic combinations 

### Performance Comparison

| | Python | Bash |
|---|---|---|
| Batch size | 100 | 25 |
| Concurrency | 5 parallel workers | Sequential |
| Typical runtime | ~9 seconds | ~2.5 minutes |
| Dependencies | python3 (stdlib only) | curl, jq, python3 |

## CSV Columns

### IOM / IOA / IAC Reports

| Column | Description | IOMs | IOAs | IAC |
|--------|-------------|------|------|-----|
| **Policy ID** | Unique identifier (UUID for IOMs/IAC, integer for IOAs) | Yes | Yes | Yes |
| **Policy Name** | Human-readable policy name | Yes | Yes | Yes |
| **Cloud Provider** | AWS, Azure, GCP, OCI, General, ASPM | Yes | Yes | Yes |
| **Resource Type** | Cloud resource type or asset type | Yes | Yes | Yes |
| **Service** | Cloud service category (e.g., S3, EC2, Identity) | Yes | Yes | Yes |
| **Origin** | `Default` or `Custom` | Yes | Yes | Yes |
| **Policy Type** | `IOM`, `IOA`, or `IAC` | Yes | Yes | Yes |
| **Description** | Detailed policy description | Yes | — | Yes |
| **Alert Logic** | Step-by-step detection logic | Yes | — | Yes |
| **Remediation Steps** | How to remediate findings | Yes | — | Yes |
| **Attack Types** | MITRE-aligned attack categories | — | Yes | — |

### Cloud Risks Report

| Column | Description |
|--------|-------------|
| **Rule ID** | Unique rule identifier (UUID) |
| **Rule Name** | Human-readable rule name (e.g., "Unused identity with excessive permissions") |
| **Severity** | `Low`, `Medium`, or `High` |
| **Cloud Provider** | AWS, Azure, GCP (semicolon-separated if multiple) |
| **Service Category** | Identity, Compute, Data, etc. |
| **Insight Categories** | Identity, Network, Vulnerabilities, Data, etc. |
| **Risk Factors** | Contributing risk factors (e.g., "Unused Identity; Excessive infra permissions") |
| **Description** | Detailed rule description |
| **Finding Count** | Total number of findings for this rule |
| **Open Count** | Number of currently open findings |
| **Resolved Count** | Number of resolved findings |

## How Classification Works

The script uses a cross-reference approach to separate cloud IOMs from IAC rules:

1. **IOAs**: Policies from `settings/entities/policy/v1` with `policy_type == "Behavioral"` — these are behavioral detections that don't exist in the cloud-policies endpoint
2. **IOMs**: Cloud-policies whose name matches a Configuration policy in `settings/entities/policy/v1` — these are cloud-native misconfigurations (e.g., S3 bucket public access, CloudTrail disabled)
3. **IAC**: Everything else from cloud-policies — Kubernetes, Docker, Helm, OpenAPI/Swagger, ASPM, and other non-cloud-native rules
4. **Cloud Risks**: Fetched from a separate endpoint (`cloud-security-risks/combined/cloud-risks/v1`) — these are toxic combinations representing multi-factor security risks (e.g., "Unused identity with excessive permissions"). The endpoint returns per-asset findings which are deduplicated by `rule_id` to produce unique rules


## API Permissions Required

Your Falcon API client needs the following scopes:
- `Cloud Security Policies:read` — for IOM and IAC policies
- `Cloud Security API Risks:read` — for IOA (Behavioral) policies and IOM classification

## Troubleshooting

### Authentication Issues
- Verify your `FALCON_CLIENT_ID` and `FALCON_CLIENT_SECRET` are correct
- Ensure your API client has the required permissions (all three scopes listed above)

### Non-US-1 Cloud Regions
Set the `FALCON_BASE_URL` environment variable to your region's API base URL:
```bash
export FALCON_BASE_URL="https://api.us-2.crowdstrike.com"  # US-2
export FALCON_BASE_URL="https://api.eu-1.crowdstrike.com"  # EU-1
```

### Missing Dependencies
- **python3**: Usually pre-installed on macOS and Linux
- **jq** (bash version only): Install with `brew install jq` (macOS) or `apt-get install jq` (Ubuntu/Debian)

## Disclaimer

This is an unofficial, community-created tool and is not affiliated with or officially supported by CrowdStrike. Use at your own risk. Always review and test scripts in a non-production environment before use.