# CSPM Policy Report Generator

A bash script to retrieve and export CrowdStrike CSPM (Cloud Security Posture Management) policy details via the Falcon API.

## Overview

This script generates a comprehensive CSV report of all CSPM policies in your CrowdStrike environment, including:
- Policy ID and Name
- Cloud Provider (AWS, Azure, GCP, OCI, General)
- Resource Type and Service
- Policy Description
- Alert Logic

## Quick Start (One-liner)

You can run the script directly without cloning the repository:

```bash
# Set your credentials
export FALCON_CLIENT_ID="your_client_id_here"
export FALCON_CLIENT_SECRET="your_client_secret_here"

# Download and run the script
curl -s https://raw.githubusercontent.com/kuhnskc/cspm-policy-report/main/get-cspm-rules.sh | bash
```

## Prerequisites

- **CrowdStrike Falcon API credentials** with CSPM read permissions
- **curl** - for API calls
- **jq** - for JSON processing
- **bash** - script interpreter

## Installation Methods

### Method 1: Direct execution (recommended for one-time use)
```bash
curl -s https://raw.githubusercontent.com/kuhnskc/cspm-policy-report/main/get-cspm-rules.sh | bash
```

### Method 2: Download and run
```bash
curl -O https://raw.githubusercontent.com/kuhnskc/cspm-policy-report/main/get-cspm-rules.sh
chmod +x get-cspm-rules.sh
./get-cspm-rules.sh
```

### Method 3: Clone repository
```bash
git clone https://github.com/kuhnskc/cspm-policy-report.git
cd cspm-policy-report
chmod +x get-cspm-rules.sh
./get-cspm-rules.sh
```

## Setup (for local installation)

1. Set your Falcon API credentials as environment variables:
```bash
export FALCON_CLIENT_ID="your_client_id_here"
export FALCON_CLIENT_SECRET="your_client_secret_here"
```

2. Make the script executable:
```bash
chmod +x get-cspm-rules.sh
```

## Usage

```bash
./get-cspm-rules.sh
```

The script will:
1. Authenticate with the Falcon API
2. Retrieve all policy IDs (with pagination)
3. Fetch detailed policy information in batches
4. Generate a timestamped CSV file: `cspm_policy_summary_YYYYMMDD_HHMMSS.csv`

## Output

The CSV contains the following columns:
- **Policy ID**: Unique identifier for the policy
- **Policy Name**: Human-readable policy name
- **Cloud Provider**: AWS, Azure, GCP, OCI, General, etc.
- **Resource Type**: Specific cloud resource type (e.g., AWS::S3::Bucket)
- **Service**: Cloud service category (e.g., S3, EC2, Virtual Machines)
- **Description**: Detailed policy description
- **Alert Logic**: Step-by-step detection logic

## Sample Output

```csv
Policy ID,Policy Name,Cloud Provider,Resource Type,Service,Description,Alert Logic
"f934cb89-32c8-4d67-9e88-0c3f446062d8","Virtual Machine allows public internet access to Docker","Azure","Microsoft.Compute/virtualMachines","Virtual Machines","Allowing ingress network traffic from the global IP space...","1. List all Virtual Machines with associated public IPs..."
```

## Supported Cloud Providers

The script automatically detects and reports policies for all cloud providers supported by CrowdStrike CSPM:
- **AWS** (Amazon Web Services)
- **Azure** (Microsoft Azure)
- **GCP** (Google Cloud Platform)
- **OCI** (Oracle Cloud Infrastructure)
- **General** (Multi-cloud/generic policies)

## Features

- **Batch processing** - Handles large numbers of policies efficiently
- **Progress tracking** - Shows real-time progress during execution
- **Error handling** - Graceful handling of API errors and rate limits
- **Clean output** - Properly formatted CSV with escaped special characters
- **Summary statistics** - Shows policy counts by cloud provider
- **One-liner execution** - Run directly from GitHub without cloning

## API Permissions Required

Your Falcon API client needs the following scopes:
- `cloud-policies:read`

## Troubleshooting

### Authentication Issues
- Verify your `FALCON_CLIENT_ID` and `FALCON_CLIENT_SECRET` are correct
- Ensure your API client has the required permissions

### Rate Limiting
The script includes built-in delays to respect API rate limits. If you encounter 429 errors, the script will automatically retry.

### Large Environments
For environments with thousands of policies, the script may take several minutes to complete. Progress is shown throughout execution.

### Missing Dependencies
- **curl**: Usually pre-installed on most systems
- **jq**: Install with `brew install jq` (macOS) or `apt-get install jq` (Ubuntu/Debian)

## Contributing

Feel free to submit issues and enhancement requests!

## Disclaimer

This is an unofficial, community-created tool and is not affiliated with or officially supported by CrowdStrike. Use at your own risk. Always review and test scripts in a non-production environment before use.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.