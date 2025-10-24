#!/bin/bash

# Step 3: Custom IOM Policy Creator
# Create Custom IOM policies using templates and user configuration

set -e

# Configuration
TEMPLATES_DIR="$(dirname "$0")/templates"
EXAMPLES_DIR="$(dirname "$0")/examples"

# Help function
show_help() {
    echo "🚀 Custom IOM Policy Creator"
    echo "==========================="
    echo ""
    echo "Create Custom Indicators of Misconfiguration policies for CrowdStrike CSPM."
    echo ""
    echo "Usage: $0 [OPTIONS] [TEMPLATE]"
    echo ""
    echo "OPTIONS:"
    echo "  -h, --help              Show this help message"
    echo "  -n, --name NAME         Policy name (will prompt if not provided)"
    echo "  -t, --template TYPE     Use template: s3, ec2, iam, security-group"
    echo "  -s, --severity LEVEL    Severity (1=Critical, 2=High, 3=Medium, 4=Low, 5=Info)"
    echo "  --interactive           Interactive mode with guided prompts"
    echo "  --list-templates        Show available policy templates"
    echo "  --dry-run               Show what would be created without deploying"
    echo ""
    echo "TEMPLATES:"
    echo "  s3                     S3 bucket security policies"
    echo "  ec2                    EC2 instance compliance policies"
    echo "  iam                    IAM user security policies"
    echo "  security-group         Security group validation policies"
    echo "  custom                 Create from scratch with prompts"
    echo ""
    echo "EXAMPLES:"
    echo "  $0 --template s3 --interactive          # Interactive S3 policy creation"
    echo "  $0 --template ec2 --name \"EC2 Tags\"     # Quick EC2 policy"
    echo "  $0 --list-templates                     # Show all available templates"
    echo "  $0 --dry-run --template iam             # Preview IAM policy"
    echo ""
    echo "WORKFLOW:"
    echo "  1. Run ./1-discover-assets.sh to find resources"
    echo "  2. Run ./2-analyze-resource-schemas.sh to understand fields"
    echo "  3. Use this script to create and deploy policies"
}

# Available templates
declare -A TEMPLATES=(
    ["s3"]="S3 Bucket Security"
    ["ec2"]="EC2 Instance Compliance"
    ["iam"]="IAM User Security"
    ["security-group"]="Security Group Validation"
    ["custom"]="Custom Policy from Scratch"
)

# List available templates
list_templates() {
    echo "📋 Available Policy Templates:"
    echo "============================="
    echo ""
    for key in "${!TEMPLATES[@]}"; do
        printf "%-15s %s\n" "$key" "${TEMPLATES[$key]}"
    done
    echo ""
    echo "💡 Use --template <name> to select a template"
    echo "💡 Use --interactive for guided policy creation"
}

# Parse command line arguments
POLICY_NAME=""
TEMPLATE=""
SEVERITY=""
INTERACTIVE=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -n|--name)
            POLICY_NAME="$2"
            shift 2
            ;;
        -t|--template)
            TEMPLATE="$2"
            shift 2
            ;;
        -s|--severity)
            SEVERITY="$2"
            shift 2
            ;;
        --interactive)
            INTERACTIVE=true
            shift
            ;;
        --list-templates)
            list_templates
            exit 0
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        *)
            if [[ -z "$TEMPLATE" ]]; then
                TEMPLATE="$1"
            else
                echo "❌ Error: Unknown option $1"
                exit 1
            fi
            shift
            ;;
    esac
done

# Check environment variables for API
if [ "$DRY_RUN" = false ]; then
    if [[ -z "$FALCON_CLIENT_ID" || -z "$FALCON_CLIENT_SECRET" ]]; then
        echo "❌ Error: Please set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables"
        echo ""
        echo "Example:"
        echo "export FALCON_CLIENT_ID='your_client_id_here'"
        echo "export FALCON_CLIENT_SECRET='your_secret_here'"
        exit 1
    fi
fi

# Check dependencies
command -v jq >/dev/null 2>&1 || { echo "❌ Error: jq is required but not installed."; exit 1; }

# Interactive template selection
if [[ "$INTERACTIVE" = true && -z "$TEMPLATE" ]]; then
    echo "🎯 Interactive Custom IOM Policy Creator"
    echo "========================================"
    echo ""
    echo "Available templates:"
    for key in "${!TEMPLATES[@]}"; do
        printf "  %-15s %s\n" "$key" "${TEMPLATES[$key]}"
    done
    echo ""
    read -p "Select a template: " TEMPLATE
fi

# Validate template
if [[ -z "$TEMPLATE" ]]; then
    echo "❌ Error: No template specified"
    echo ""
    show_help
    exit 1
fi

if [[ -z "${TEMPLATES[$TEMPLATE]}" ]]; then
    echo "❌ Error: Unknown template '$TEMPLATE'"
    echo ""
    list_templates
    exit 1
fi

# Template-specific policy generators
generate_s3_policy() {
    local name="$1"
    local severity="$2"

    cat << EOF
{
  "name": "$name",
  "description": "Custom IOM to detect S3 buckets that allow public read or write access, ensuring data security and compliance",
  "platform": "AWS",
  "provider": "AWS",
  "resource_type": "AWS::S3::Bucket",
  "domain": "CSPM",
  "subdomain": "IOM",
  "severity": $severity,
  "logic": "package crowdstrike\\n\\ndefault result := \\"pass\\"\\n\\n# Fail if bucket allows public read access\\nresult := \\"fail\\" if {\\n    input.cloud_context.allows_public_read == true\\n}\\n\\n# Fail if bucket allows public write access\\nresult := \\"fail\\" if {\\n    input.cloud_context.allows_public_write == true\\n}\\n\\n# Pass only if bucket is properly secured\\nresult := \\"pass\\" if {\\n    input.active == true\\n    input.cloud_context.allows_public_read == false\\n    input.cloud_context.allows_public_write == false\\n}",
  "alert_info": "S3 bucket allows public access which poses significant security risk for data exposure and unauthorized access",
  "remediation_info": "Navigate to AWS S3 console|Select the non-compliant bucket|Click Permissions tab|Review Bucket Policy and ACLs for public access grants|Remove any public read or write permissions|Enable Block Public Access settings at bucket level|Verify changes by testing access from external sources|Document changes for compliance tracking",
  "attack_types": "Data Exposure"
}
EOF
}

generate_ec2_policy() {
    local name="$1"
    local severity="$2"

    cat << EOF
{
  "name": "$name",
  "description": "Custom IOM to ensure EC2 instances have required management and security tags for proper governance and cost tracking",
  "platform": "AWS",
  "provider": "AWS",
  "resource_type": "AWS::EC2::Instance",
  "domain": "CSPM",
  "subdomain": "IOM",
  "severity": $severity,
  "logic": "package crowdstrike\\n\\ndefault result := \\"fail\\"\\n\\n# Required tags for compliance\\nrequired_tags := [\\"Environment\\", \\"Owner\\", \\"Project\\"]\\n\\n# Helper function to check if tag exists and has value\\nhas_tag(tag_name) if {\\n    input.tags[tag_name]\\n    input.tags[tag_name] != \\"\\"\\n}\\n\\n# Pass if all required tags are present and instance is active\\nresult := \\"pass\\" if {\\n    input.active == true\\n    count([tag | tag := required_tags[_]; has_tag(tag)]) == count(required_tags)\\n    input.tags[\\"Environment\\"] in [\\"dev\\", \\"staging\\", \\"prod\\", \\"test\\"]\\n}",
  "alert_info": "EC2 instance is missing required tags for proper resource management, cost tracking, and operational governance",
  "remediation_info": "Navigate to AWS EC2 console|Select the non-compliant instance|Click Tags tab and select Manage tags|Add missing required tags: Environment (dev/staging/prod/test), Owner (team or individual responsible), Project (associated project name)|Ensure tag values follow organizational naming conventions|Click Save changes to apply tags|Update any automation or billing reports to include new tags",
  "attack_types": "Misconfiguration"
}
EOF
}

generate_iam_policy() {
    local name="$1"
    local severity="$2"

    cat << EOF
{
  "name": "$name",
  "description": "Custom IOM to ensure IAM users have Multi-Factor Authentication enabled for enhanced account security and access control",
  "platform": "AWS",
  "provider": "AWS",
  "resource_type": "AWS::IAM::User",
  "domain": "CSPM",
  "subdomain": "IOM",
  "severity": $severity,
  "logic": "package crowdstrike\\n\\ndefault result := \\"fail\\"\\n\\n# Check if user is a service account\\nis_service_account if {\\n    startswith(input.resource_id, \\"svc-\\")\\n}\\n\\nis_service_account if {\\n    startswith(input.resource_id, \\"service-\\")\\n}\\n\\n# Human users must have MFA enabled\\nresult := \\"pass\\" if {\\n    input.active == true\\n    not is_service_account\\n    input.cloud_context.mfa_enabled == true\\n}\\n\\n# Service accounts with proper naming pass\\nresult := \\"pass\\" if {\\n    input.active == true\\n    is_service_account\\n}\\n\\n# Explicit fail for root user\\nresult := \\"fail\\" if {\\n    input.resource_id == \\"root\\"\\n}",
  "alert_info": "IAM user does not have Multi-Factor Authentication enabled, creating security vulnerability for potential account compromise and unauthorized access",
  "remediation_info": "Navigate to AWS IAM console|Select Users from the left navigation menu|Click on the non-compliant username|Go to Security credentials tab|In Multi-factor authentication section click Assign MFA device|Choose Virtual MFA device and follow the setup wizard|Scan QR code with authenticator app (Google Authenticator, Authy, etc.)|Enter two consecutive authentication codes to verify setup|Click Assign MFA to complete the configuration|Test MFA login to ensure proper functionality",
  "attack_types": "Credential Compromise"
}
EOF
}

generate_sg_policy() {
    local name="$1"
    local severity="$2"

    cat << EOF
{
  "name": "$name",
  "description": "Custom IOM to detect security groups that allow unrestricted access to dangerous ports, preventing potential security breaches",
  "platform": "AWS",
  "provider": "AWS",
  "resource_type": "AWS::EC2::SecurityGroup",
  "domain": "CSPM",
  "subdomain": "IOM",
  "severity": $severity,
  "logic": "package crowdstrike\\n\\ndefault result := \\"pass\\"\\n\\n# Dangerous ports that should not be open to 0.0.0.0/0\\ndangerous_ports := [22, 3389, 1433, 3306, 5432, 1521, 27017, 6379]\\n\\n# Check for unrestricted access to dangerous ports\\nhas_unrestricted_dangerous_access if {\\n    rule := input.cloud_context.ingress_rules[_]\\n    rule.cidr_blocks[_] == \\"0.0.0.0/0\\"\\n    rule.port in dangerous_ports\\n}\\n\\n# Fail if unrestricted access to dangerous ports\\nresult := \\"fail\\" if {\\n    input.active == true\\n    has_unrestricted_dangerous_access\\n}\\n\\n# Pass if no unrestricted dangerous access\\nresult := \\"pass\\" if {\\n    input.active == true\\n    not has_unrestricted_dangerous_access\\n}",
  "alert_info": "Security group allows unrestricted internet access (0.0.0.0/0) to dangerous ports including SSH, RDP, and database ports",
  "remediation_info": "Navigate to AWS EC2 console|Go to Security Groups in the left navigation|Select the non-compliant security group|Click Inbound rules tab|Review rules allowing 0.0.0.0/0 access to ports 22 (SSH), 3389 (RDP), or database ports|Edit or delete overly permissive rules|Replace with specific IP ranges or security group references|For SSH/RDP access, use bastion hosts or VPN connections|For database access, ensure only application security groups have access|Test connectivity after changes to ensure services still function properly",
  "attack_types": "Network Exposure"
}
EOF
}

# Interactive customization
interactive_customize() {
    local template="$1"

    echo ""
    echo "🎯 Customizing $template Policy"
    echo "$(printf '=%.0s' {1..30})"

    # Get policy name
    if [[ -z "$POLICY_NAME" ]]; then
        read -p "Enter policy name: " POLICY_NAME
    fi

    # Get severity
    if [[ -z "$SEVERITY" ]]; then
        echo ""
        echo "Select severity level:"
        echo "1 - Critical (Red)"
        echo "2 - High (Orange)"
        echo "3 - Medium (Yellow)"
        echo "4 - Low (Blue)"
        echo "5 - Info (Gray)"
        read -p "Severity (1-5): " SEVERITY
    fi

    # Validate severity
    if [[ ! "$SEVERITY" =~ ^[1-5]$ ]]; then
        echo "❌ Invalid severity. Using Medium (3)"
        SEVERITY=3
    fi

    # Template-specific customizations
    case $template in
        "s3")
            echo ""
            echo "💡 S3 Policy Options:"
            echo "This policy will check for public read/write access."
            echo "You can modify the Rego logic later to add:"
            echo "• Encryption requirements"
            echo "• Specific tag validation"
            echo "• Versioning requirements"
            ;;
        "ec2")
            echo ""
            echo "💡 EC2 Policy Options:"
            echo "This policy checks for required tags: Environment, Owner, Project"
            echo "You can modify to add:"
            echo "• Instance type restrictions"
            echo "• Region compliance"
            echo "• Security group validation"
            ;;
        "iam")
            echo ""
            echo "💡 IAM Policy Options:"
            echo "This policy enforces MFA for human users, allows service accounts"
            echo "You can modify to add:"
            echo "• Password policy checks"
            echo "• Access key age limits"
            echo "• Group membership requirements"
            ;;
        "security-group")
            echo ""
            echo "💡 Security Group Policy Options:"
            echo "This policy blocks 0.0.0.0/0 access to dangerous ports"
            echo "You can modify to add:"
            echo "• Specific port restrictions"
            echo "• Description requirements"
            echo "• Egress rule validation"
            ;;
    esac

    read -p "Press Enter to continue..."
}

# Get authentication token
get_auth_token() {
    if [ "$DRY_RUN" = true ]; then
        echo "fake_token_for_dry_run"
        return
    fi

    echo "🔐 Getting Falcon API Token..."

    TOKEN_RESPONSE=$(curl -s -X POST "https://api.crowdstrike.com/oauth2/token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -H "Authorization: Basic $(echo -n "${FALCON_CLIENT_ID}:${FALCON_CLIENT_SECRET}" | base64)" \
      -d "grant_type=client_credentials")

    TOKEN=$(echo $TOKEN_RESPONSE | jq -r '.access_token')

    if [ "$TOKEN" = "null" ] || [ -z "$TOKEN" ]; then
        echo "❌ Failed to get token"
        echo $TOKEN_RESPONSE
        exit 1
    fi

    echo "✅ Token obtained successfully"
    echo "$TOKEN"
}

# Deploy policy
deploy_policy() {
    local policy_json="$1"
    local token="$2"

    if [ "$DRY_RUN" = true ]; then
        echo ""
        echo "🔍 DRY RUN - Policy that would be created:"
        echo "$(printf '=%.0s' {1..45})"
        echo "$policy_json" | jq .
        echo ""
        echo "💡 Remove --dry-run flag to actually deploy this policy"
        return
    fi

    echo ""
    echo "🚀 Deploying Custom IOM Policy..."

    RESPONSE=$(curl -s -X POST "https://api.crowdstrike.com/cloud-policies/entities/rules/v1" \
      -H "Authorization: Bearer $token" \
      -H "Content-Type: application/json" \
      -d "$policy_json")

    RULE_ID=$(echo $RESPONSE | jq -r '.resources[0].uuid // empty')
    ERROR=$(echo $RESPONSE | jq -r '.errors[0].message // empty')

    if [ -n "$RULE_ID" ]; then
        echo "✅ Policy Created Successfully!"
        echo "   Policy ID: $RULE_ID"
        echo "   Name: $POLICY_NAME"
        echo ""
        echo "🎯 Your Custom IOM is now active and will evaluate resources."
        echo "   Check the CrowdStrike Falcon console for policy findings."
    else
        echo "❌ Policy Creation Failed: $ERROR"
        echo ""
        echo "Full response:"
        echo "$RESPONSE" | jq .
        exit 1
    fi
}

# Main execution
echo "🚀 Custom IOM Policy Creator"
echo "============================"

# Interactive flow
if [ "$INTERACTIVE" = true ]; then
    interactive_customize "$TEMPLATE"
fi

# Set defaults if not provided
if [[ -z "$POLICY_NAME" ]]; then
    POLICY_NAME="${TEMPLATES[$TEMPLATE]} Policy"
fi

if [[ -z "$SEVERITY" ]]; then
    SEVERITY=2  # Default to High
fi

echo ""
echo "📋 Policy Configuration:"
echo "  Template: $TEMPLATE (${TEMPLATES[$TEMPLATE]})"
echo "  Name: $POLICY_NAME"
echo "  Severity: $SEVERITY"

# Generate policy JSON
echo ""
echo "⚙️  Generating policy from template..."

case $TEMPLATE in
    "s3")
        POLICY_JSON=$(generate_s3_policy "$POLICY_NAME" "$SEVERITY")
        ;;
    "ec2")
        POLICY_JSON=$(generate_ec2_policy "$POLICY_NAME" "$SEVERITY")
        ;;
    "iam")
        POLICY_JSON=$(generate_iam_policy "$POLICY_NAME" "$SEVERITY")
        ;;
    "security-group")
        POLICY_JSON=$(generate_sg_policy "$POLICY_NAME" "$SEVERITY")
        ;;
    *)
        echo "❌ Template generator not implemented for: $TEMPLATE"
        exit 1
        ;;
esac

# Get authentication and deploy
TOKEN=$(get_auth_token)
deploy_policy "$POLICY_JSON" "$TOKEN"

if [ "$DRY_RUN" = false ]; then
    echo ""
    echo "🔄 Next Steps:"
    echo "1. Monitor the policy in CrowdStrike console for findings"
    echo "2. Adjust policy logic if you get false positives"
    echo "3. Create additional policies for other resource types"
    echo ""
    echo "💡 To modify this policy:"
    echo "   • Use the CrowdStrike console UI, or"
    echo "   • Modify the Rego logic and redeploy"
fi