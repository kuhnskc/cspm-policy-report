# Custom IOM (Indicators of Misconfiguration) Development

This directory provides a complete workflow for creating Custom Indicators of Misconfiguration (IOMs) in CrowdStrike CSPM using the Falcon API and Rego language.

## 🚀 Quick Start

```bash
# Set your CrowdStrike API credentials
export FALCON_CLIENT_ID="your_client_id"
export FALCON_CLIENT_SECRET="your_client_secret"

# Step 1: Discover assets in your environment
./1-discover-assets.sh s3

# Step 2: Analyze resource fields for Rego development
./2-analyze-resource-schemas.sh s3_sample_schema.json

# Step 3: Create and deploy Custom IOM policies
./3-create-custom-iom.sh --template s3 --interactive
```

## 📋 Complete Workflow

### The Asset-to-Policy Pipeline

Custom IOM development follows a structured pipeline from asset discovery to policy deployment:

```
Asset Discovery → Field Analysis → Rego Development → Policy Creation → Deployment
```

## 🧠 Understanding the Files

### `.rego` Files (Learning Examples)
- **Location:** `examples/` directory
- **Purpose:** Reference examples showing Rego syntax patterns
- **Usage:** Study these to learn how to write Rego rules
- **Examples:** `lambda-security-rules.rego`, `s3-security-rules.rego`

### `.json` Files (Deployment Templates)
- **Location:** `templates/` directory
- **Purpose:** Complete policy templates ready for deployment
- **Structure:** Contains Rego logic embedded in the `"logic"` field as a string
- **Usage:** Deploy immediately or use as deployment format reference

### Sample Files (Demo Examples)
- **`lambda_sample_schema.json`** - Real Asset API response showing data structure
- **Purpose:** Shows exactly what fields are available for your Rego rules

## 🔍 How Field Discovery Works

**Key Insight:** CrowdStrike's Asset API response structure becomes your Rego `input.*` object.

When you run Step 1, it queries the CrowdStrike Asset API and gets real resource data like:
```json
{
  "resource_type": "AWS::Lambda::Function",
  "tags": {"Environment": "prod"},
  "cloud_context": {"runtime": "python3.11", "timeout": 30}
}
```

Step 2 analyzes this JSON and shows you **every available field** for Rego rules:
- `input.resource_type` → `"AWS::Lambda::Function"`
- `input.tags.Environment` → `"prod"`
- `input.cloud_context.runtime` → `"python3.11"`
- `input.cloud_context.timeout` → `30`

**Result:** You can write Rego rules against ANY field that exists in your actual cloud resources!

## 🎯 Template vs Custom Policy Creation

### Using Predefined Templates
```bash
./3-create-custom-iom.sh --template s3 --interactive
./3-create-custom-iom.sh --template ec2 --interactive
```
- Uses pre-built policies from `templates/` directory
- Ready-to-deploy with proven Rego logic
- Good for common security patterns

### Creating Custom Policies
```bash
./3-create-custom-iom.sh --template custom --interactive
```
- Script prompts you to paste your own Rego code
- Write custom logic based on Steps 1 & 2 discovery
- Full flexibility for your specific requirements

**Workflow:** Discover assets → Analyze fields → Study examples → Write custom Rego → Deploy via custom template

### Step 1: Asset Discovery (`1-discover-assets.sh`)

**Purpose:** Find cloud resources in your environment to understand what you can create policies for.

**Usage:**
```bash
# Find S3 buckets
./1-discover-assets.sh s3

# Find EC2 instances
./1-discover-assets.sh ec2 --limit 20

# Overview of all AWS resources
./1-discover-assets.sh --all --cloud aws

# List available resource types
./1-discover-assets.sh --list-types
```

**What it does:**
- Queries CrowdStrike Asset API for resources
- Shows resource counts by type
- Extracts sample resource with full schema
- Saves JSON files with available fields for Rego development

**Output:**
- `{resource_type}_sample_schema.json` - Sample resource with all available fields
- Console display of key fields, tags, and cloud context

### Step 2: Resource Schema Analysis (`2-analyze-resource-schemas.sh`)

**Purpose:** Analyze resource schemas to understand what fields are available for Rego rule conditions.

**Usage:**
```bash
# Analyze existing schema file
./2-analyze-resource-schemas.sh s3_sample_schema.json

# Interactive exploration
./2-analyze-resource-schemas.sh --type ec2 --interactive

# Generate analysis report
./2-analyze-resource-schemas.sh s3_sample_schema.json --output ./analysis/
```

**What it does:**
- Examines JSON schema files from Step 1
- Identifies available fields for Rego rules
- Suggests common rule patterns based on resource type
- Generates comprehensive analysis reports
- Provides interactive exploration of field structures

**Output:**
- `{resource}_analysis.md` - Detailed field documentation
- Suggested Rego patterns for the resource type
- Interactive field exploration (optional)

### Step 3: Custom IOM Policy Creation (`3-create-custom-iom.sh`)

**Purpose:** Create and deploy Custom IOM policies using templates or custom Rego logic.

**Usage:**
```bash
# Interactive S3 policy creation
./3-create-custom-iom.sh --template s3 --interactive

# Quick EC2 policy with name
./3-create-custom-iom.sh --template ec2 --name "EC2 Tagging Policy"

# Preview policy without deploying
./3-create-custom-iom.sh --template iam --dry-run

# List available templates
./3-create-custom-iom.sh --list-templates
```

**What it does:**
- Uses pre-built templates for common resource types
- Generates proper CSPM policy JSON with working Rego logic
- Authenticates with CrowdStrike API and deploys policies
- Provides interactive customization options

**Available Templates:**
- **s3** - S3 bucket public access prevention
- **ec2** - EC2 instance tagging compliance
- **iam** - IAM user MFA enforcement
- **security-group** - Security group dangerous port restrictions

## 📁 Directory Structure

```
custom-iom/
├── README.md                          # This file
├── 1-discover-assets.sh              # Asset discovery script
├── 2-analyze-resource-schemas.sh     # Schema analysis script
├── 3-create-custom-iom.sh            # Policy creation script
├── examples/                         # Rego rule examples
│   ├── s3-security-rules.rego        # S3 bucket security patterns
│   ├── ec2-compliance-rules.rego     # EC2 compliance patterns
│   ├── iam-security-rules.rego       # IAM security patterns
│   └── lambda-security-rules.rego    # Lambda security patterns
└── templates/                        # JSON policy templates
    ├── s3-policy-template.json       # S3 policy template
    ├── ec2-policy-template.json      # EC2 policy template
    ├── iam-policy-template.json      # IAM policy template
    └── lambda-policy-template.json   # Lambda policy template
```

## 🔧 Prerequisites

- **CrowdStrike Falcon API credentials** with CSPM permissions
- **curl** - for API calls
- **jq** - for JSON processing
- **bash** - script interpreter

### API Permissions Required

Your Falcon API client needs these scopes:
- `cloud-security-assessment:read` - For asset discovery
- `cloud-policies:read` - For reading existing policies
- `cloud-policies:write` - For creating Custom IOMs

### Setting Up Credentials

```bash
export FALCON_CLIENT_ID="your_client_id_here"
export FALCON_CLIENT_SECRET="your_client_secret_here"
```