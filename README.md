# CSPM Policy Report Generator

Scripts to retrieve and export CrowdStrike CSPM (Cloud Security Posture Management) policy details via the Falcon API. Generates five separate CSV reports covering **IOMs** (cloud misconfigurations), **IOAs** (behavioral detections), **Insights** (identity, exposure, sensitivity, and ASPM), **IAC rules** (infrastructure-as-code / container / API security), and **Cloud Risks** (toxic combinations).

## Overview

This tool generates comprehensive CSV reports of all CSPM policies in your CrowdStrike environment:

- **IOM Report** — Indicators of Misconfiguration (default and custom cloud configuration policies)
- **IOA Report** — Indicators of Attack (behavioral detection policies with MITRE ATT&CK-aligned attack types)
- **Insights Report** — Identity risk, internet exposure, sensitive data, backup status, and ASPM application insights
- **IAC Report** — Infrastructure-as-Code rules (Kubernetes, Docker, Helm, OpenAPI/Swagger, and other scanning rules)
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

### Options

| Flag | Description |
|---|---|
| `--provider VALUE` | Filter all reports to a specific cloud provider (e.g., `AWS`, `Azure`, `GCP`, `OCI`) |
| `--sort-by-id` | Sort rows by Policy ID / Rule ID |

```bash
# Export only AWS policies, sorted by ID
python3 get-cspm-rules.py --provider AWS --sort-by-id

# Export only Azure policies
bash get-cspm-rules.sh --provider Azure
```

Both scripts will:
1. Authenticate with the Falcon API
2. Fetch `settings/entities/policy/v1` to get IOA (Behavioral) policies
3. Retrieve all cloud-policy IDs via `cloud-policies/queries/rules/v1` (with pagination)
4. Fetch detailed cloud-policy information in batches via `cloud-policies/entities/rules/v1`
5. Classify each cloud-policy by its `subdomain` field: **IOM**, **Insight**, or **IAC**
6. Fetch cloud risks via `cloud-security-risks/combined/cloud-risks/v1` and deduplicate by rule
7. Generate five timestamped CSV files and display summary statistics

### Output Files

| File | Contents |
|---|---|
| `cspm_iom_report_TIMESTAMP.csv` | Cloud misconfigurations (AWS, Azure, GCP, OCI) |
| `cspm_ioa_report_TIMESTAMP.csv` | Behavioral detections (AWS, Azure) |
| `cspm_insights_report_TIMESTAMP.csv` | Identity, exposure, sensitivity, and ASPM insights |
| `cspm_iac_report_TIMESTAMP.csv` | IAC / container / API security scanning rules |
| `cspm_cloud_risks_report_TIMESTAMP.csv` | Cloud risks / toxic combinations |


## How Classification Works

Each cloud-policy from the `/cloud-policies/entities/rules/v1` endpoint includes a `subdomain` field that the script uses for classification:

| `subdomain` value | Report | Description |
|---|---|---|
| `IOM` | IOM CSV | Cloud-native misconfigurations (e.g., S3 bucket public access, CloudTrail disabled) |
| `Insight` | Insights CSV | Identity risk, internet exposure, sensitive data detection, ASPM application insights |
| `IAC` | IAC CSV | Infrastructure-as-code scanning rules (Kubernetes, Docker, Helm, OpenAPI/Swagger) |
| `CloudRisk` | (skipped) | Covered by the dedicated cloud-risks endpoint instead |

Additionally:
- **IOAs**: Fetched from a separate endpoint (`settings/entities/policy/v1`) with `policy_type == "Behavioral"` — behavioral detections that don't exist in the cloud-policies endpoint
- **Cloud Risks**: Fetched from `cloud-security-risks/combined/cloud-risks/v1` — toxic combinations representing multi-factor security risks. The endpoint returns per-asset findings which are deduplicated by `rule_id` to produce unique rules

## API Endpoints Used

### `GET /cloud-policies/queries/rules/v1`
Returns paginated IDs for all cloud-policies. Used to enumerate every policy before fetching details.
- **Pagination**: `limit` (max 500) + `offset`
- **Returns**: Array of UUID strings

### `GET /cloud-policies/entities/rules/v1`
Returns full policy details for a batch of IDs. This is the primary data source for **IOM**, **Insight**, and **IAC** reports.
- **Parameters**: `ids` (pass multiple)
- **Key fields**: `uuid`, `name`, `provider`, `subdomain`, `description`, `alert_info`, `remediation`, `resource_types`, `origin`
- **Classification**: The `subdomain` field determines the report — `"IOM"`, `"Insight"`, `"IAC"`, or `"CloudRisk"`

### `GET /settings/entities/policy/v1`
Returns all CSPM settings policies in a single response (no pagination). Used exclusively for the **IOA** report.
- **Filter**: `policy_type == "Behavioral"` selects IOA policies
- **Key fields**: `policy_id`, `name`, `cloud_provider`, `cloud_asset_type`, `cloud_service_friendly`, `attack_types`

### `GET /cloud-security-risks/combined/cloud-risks/v1`
Returns per-asset cloud risk findings. Used for the **Cloud Risks** report after deduplication by `rule_id`.
- **Pagination**: `limit` (max 1000) + `offset`
- **Key fields**: `rule_id`, `rule_name`, `rule_description`, `severity`, `provider`, `service_category`, `risk_factors`, `status`
- **Deduplication**: Multiple findings per rule (one per affected asset) — the script aggregates to unique rules with open/resolved counts

## API Permissions Required

Your Falcon API client needs the following scopes:
- `Cloud Security Policies:read` — for IOM, Insight, and IAC policies
- `Cloud Security API Risks:read` — for IOA (Behavioral) policies and Cloud Risks

## Troubleshooting

### Authentication Issues
- Verify your `FALCON_CLIENT_ID` and `FALCON_CLIENT_SECRET` are correct
- Ensure your API client has the required permissions (both scopes listed above)

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
