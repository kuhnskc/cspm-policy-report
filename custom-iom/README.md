# Custom IOM Development Toolkit

Create and manage Custom Indicators of Misconfiguration (IOMs) for CrowdStrike CSPM using Rego policies with an intuitive interactive interface.

## Overview

Custom IOMs allow you to create tailored security policies for your cloud resources using the **Rego language**. This Python toolkit provides a comprehensive interactive interface for discovering resources, creating policies, testing Rego logic, and managing Custom IOMs in your CrowdStrike CSPM environment.

### What You Can Do

- **Browse and manage existing policies** with an intuitive menu interface
- **Create new Custom IOMs** with guided policy creation
- **Edit policy components** including descriptions, severity, alert logic, and remediation steps
- **Test Rego policies** against real resources with comprehensive error reporting
- **Update Rego logic** with built-in testing and validation
- **Multi-line formatting support** with pipe-separated format for proper display

## Quick Start

### Setup

```bash
# One-time setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Set credentials
export FALCON_CLIENT_ID="your_client_id"
export FALCON_CLIENT_SECRET="your_client_secret"
```

### Basic Usage

```bash
# Interactive toolkit (recommended)
python custom_iom_toolkit.py

# The toolkit provides an interactive menu with options to:
# 1. List all Custom IOMs
# 2. Create a new Custom IOM
# 3. Manage existing policies (edit, update, test)
# 4. Test Rego policies against live resources
```

## Project Structure

```
custom-iom/
├── README.md                    # This documentation
├── custom_iom_toolkit.py        # Main Python toolkit
├── requirements.txt             # Dependencies: requests
├── simple_examples/             # Example Rego policies
│   ├── s3_security.rego         # S3 bucket security
│   ├── ec2_tagging.rego         # EC2 instance tagging
│   └── ecr_cross_account.rego   # ECR cross-account access
└── venv/                        # Python virtual environment
```

## Key Features

### Interactive Menu Interface

The toolkit features a user-friendly menu system with:

- **Colorful interface** with clear navigation and visual feedback
- **Policy management** - browse, create, edit, and test Custom IOMs
- **Real-time testing** - validate Rego policies against live cloud resources
- **Integrated text editor** - edit policies using your preferred editor (VS Code, vim, nano)

### Policy Testing & Validation

- **Live resource testing** - test policies against real cloud resources
- **Comprehensive error reporting** - detailed feedback on Rego syntax issues
- **Resource discovery** - automatically find suitable resources for testing
- **Post-test workflow** - seamless editing and saving after successful tests

### Policy Management

- **Preserve existing data** - updating Rego logic preserves remediation steps
- **Smart formatting** - prevents duplication of step numbering
- **Complete CRUD operations** - create, read, update policies through the interface

### Example Policy: EC2 Security Groups

```rego
package crowdstrike

default result := "pass"

# Fail if EC2 instance has overly permissive security group
result = "fail" if {
    input.resource_type == "AWS::EC2::Instance"
    sg := input.security_groups[_]
    sg.configuration.ipPermissions[_].ipRanges[_].cidrIp == "0.0.0.0/0"
}
```

## Available Features

### Main Menu Options

1. **📋 List all Custom IOMs** - Browse existing policies with detailed information
2. **➕ Create new Custom IOM** - Guided policy creation with templates
3. **💾 Exit** - Clean exit from the toolkit

### Policy Management (when viewing a policy)

1. **📝 Edit Description** - Update policy description
2. **⚠️ Edit Severity** - Change severity level (0-Critical to 3-Low)
3. **🚨 Edit Alert Logic** - Multi-line alert information with pipe formatting
4. **🔧 Edit Remediation Steps** - Multi-line remediation instructions
5. **📜 Update Rego Logic** - Edit and test Rego policy code
6. **🔙 Back to Policy List** - Return to main policy listing

## API Status

| Feature | Endpoint | Status | Notes |
|---------|----------|--------|-------|
| Authentication | `/oauth2/token` | ✅ Working | Fully functional |
| Policy Listing | `/cloud-policies/queries/policies/v1` | ✅ Working | Custom IOM discovery |
| Policy Details | `/cloud-policies/entities/policies/v1` | ✅ Working | Full policy information |
| Policy Creation | `/cloud-policies/entities/policies/v1` | ✅ Working | Create new Custom IOMs |
| Policy Updates | `/cloud-policies/entities/policies/v1` | ✅ Working | Edit existing policies |
| Resource Discovery | `/cloud-security-assets/queries/resources/v1` | ✅ Working | Find resources for testing |
| Policy Testing | `/cloud-policies/entities/evaluation/v1` | ✅ Working | Rego evaluation against live resources |

## Requirements

- **Python 3.7+**
- **CrowdStrike API credentials** with these permissions:
  - `Cloud Security API Assets:READ` - For resource discovery
  - `Cloud Security Policies:READ` - For policy listing and testing
  - `Cloud Security Policies:WRITE` - For policy creation and updates

## Common Resource Types

### AWS
- `AWS::EC2::Instance` - EC2 instances
- `AWS::S3::Bucket` - S3 buckets
- `AWS::EC2::SecurityGroup` - Security groups
- `AWS::IAM::Role` - IAM roles
- `AWS::Lambda::Function` - Lambda functions

### Azure
- `Microsoft.Compute/virtualMachines` - Virtual machines
- `Microsoft.Storage/storageAccounts` - Storage accounts
- `Microsoft.Network/networkSecurityGroups` - Network security groups

### GCP
- `compute.googleapis.com/Instance` - Compute instances
- `storage.googleapis.com/Bucket` - Storage buckets
- `compute.googleapis.com/Firewall` - Firewall rules

## Policy Development Workflow

1. **Run the Toolkit**: Start with `python custom_iom_toolkit.py`
2. **Browse Existing Policies**: Review current Custom IOMs
3. **Create New Policy**: Use the guided creation process
4. **Edit Components**: Set description, severity, alert logic, and remediation steps
5. **Write Rego Logic**: Create policy rules using the Rego language
6. **Test Policy**: Validate against live cloud resources
7. **Iterate**: Edit and retest until policy works correctly

### Multi-line Formatting Tips

For **Alert Logic** and **Remediation Steps**, use pipe-separated format:
```
Navigate to AWS Console|Select the resource|Review the configuration|Make necessary changes
```

This will display as:
```
1. Navigate to AWS Console
2. Select the resource
3. Review the configuration
4. Make necessary changes
```

## Examples

See the `simple_examples/` directory for ready-to-use policies:
- **S3 Security**: Check for public access and required tags
- **EC2 Tagging**: Validate instance tagging compliance
- **ECR Cross-Account**: Control cross-account registry access

