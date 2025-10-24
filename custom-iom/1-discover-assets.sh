#!/bin/bash

# Step 1: Flexible Asset Discovery for Custom IOM Development
# Discover cloud resources to understand what's available for policy creation

set -e

# Configuration - Users can easily modify these
DEFAULT_LIMIT=10  # How many resources to show per type
DEFAULT_CLOUD_PROVIDER="aws"  # Default cloud provider

# Common resource types - Users can easily add/modify
declare -A RESOURCE_TYPES=(
    # AWS Resources
    ["s3"]="AWS::S3::Bucket"
    ["ec2"]="AWS::EC2::Instance"
    ["iam-users"]="AWS::IAM::User"
    ["iam-roles"]="AWS::IAM::Role"
    ["security-groups"]="AWS::EC2::SecurityGroup"
    ["rds"]="AWS::RDS::DBInstance"
    ["lambda"]="AWS::Lambda::Function"
    ["vpc"]="AWS::EC2::VPC"
    ["ebs"]="AWS::EC2::Volume"
    ["cloudtrail"]="AWS::CloudTrail::Trail"

    # Azure Resources
    ["azure-vm"]="Microsoft.Compute/virtualMachines"
    ["azure-storage"]="Microsoft.Storage/storageAccounts"
    ["azure-sql"]="Microsoft.Sql/servers"
    ["azure-keyvault"]="Microsoft.KeyVault/vaults"

    # GCP Resources
    ["gcp-compute"]="compute.googleapis.com/Instance"
    ["gcp-storage"]="storage.googleapis.com/Bucket"
    ["gcp-sql"]="sqladmin.googleapis.com/Instance"
)

# Help function
show_help() {
    echo "🔍 Asset Discovery for Custom IOM Development"
    echo "============================================="
    echo ""
    echo "Usage: $0 [OPTIONS] [RESOURCE_TYPE]"
    echo ""
    echo "OPTIONS:"
    echo "  -h, --help              Show this help message"
    echo "  -l, --limit NUM         Number of resources to show (default: $DEFAULT_LIMIT)"
    echo "  -c, --cloud PROVIDER    Cloud provider: aws, azure, gcp (default: $DEFAULT_CLOUD_PROVIDER)"
    echo "  --list-types            Show all available resource types"
    echo "  --all                   Discover all resource types (overview mode)"
    echo ""
    echo "RESOURCE_TYPE:"
    echo "  Specify what to discover (e.g., s3, ec2, iam-users)"
    echo "  Use --list-types to see all available options"
    echo ""
    echo "EXAMPLES:"
    echo "  $0 s3                   # Find S3 buckets"
    echo "  $0 ec2 --limit 20       # Find 20 EC2 instances"
    echo "  $0 --all --cloud azure  # Overview of all Azure resources"
    echo "  $0 iam-users --limit 5  # Find 5 IAM users"
    echo ""
    echo "AUTHENTICATION:"
    echo "  Set environment variables:"
    echo "  export FALCON_CLIENT_ID='your_client_id'"
    echo "  export FALCON_CLIENT_SECRET='your_client_secret'"
}

# List available resource types
list_resource_types() {
    echo "📋 Available Resource Types:"
    echo "==========================="
    echo ""
    echo "AWS Resources:"
    for key in "${!RESOURCE_TYPES[@]}"; do
        if [[ $key == aws* ]] || [[ ${RESOURCE_TYPES[$key]} == AWS::* ]]; then
            printf "  %-20s %s\n" "$key" "${RESOURCE_TYPES[$key]}"
        fi
    done | sort

    echo ""
    echo "Azure Resources:"
    for key in "${!RESOURCE_TYPES[@]}"; do
        if [[ $key == azure* ]] || [[ ${RESOURCE_TYPES[$key]} == Microsoft.* ]]; then
            printf "  %-20s %s\n" "$key" "${RESOURCE_TYPES[$key]}"
        fi
    done | sort

    echo ""
    echo "GCP Resources:"
    for key in "${!RESOURCE_TYPES[@]}"; do
        if [[ $key == gcp* ]] || [[ ${RESOURCE_TYPES[$key]} == *.googleapis.com/* ]]; then
            printf "  %-20s %s\n" "$key" "${RESOURCE_TYPES[$key]}"
        fi
    done | sort
}

# Parse command line arguments
LIMIT=$DEFAULT_LIMIT
CLOUD_PROVIDER=$DEFAULT_CLOUD_PROVIDER
RESOURCE_TYPE=""
SHOW_ALL=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -l|--limit)
            LIMIT="$2"
            shift 2
            ;;
        -c|--cloud)
            CLOUD_PROVIDER="$2"
            shift 2
            ;;
        --list-types)
            list_resource_types
            exit 0
            ;;
        --all)
            SHOW_ALL=true
            shift
            ;;
        *)
            if [[ -z "$RESOURCE_TYPE" ]]; then
                RESOURCE_TYPE="$1"
            else
                echo "❌ Error: Multiple resource types specified"
                exit 1
            fi
            shift
            ;;
    esac
done

# Check environment variables
if [[ -z "$FALCON_CLIENT_ID" || -z "$FALCON_CLIENT_SECRET" ]]; then
    echo "❌ Error: Please set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables"
    echo ""
    echo "Example:"
    echo "export FALCON_CLIENT_ID='your_client_id_here'"
    echo "export FALCON_CLIENT_SECRET='your_secret_here'"
    exit 1
fi

# Check dependencies
command -v curl >/dev/null 2>&1 || { echo "❌ Error: curl is required but not installed."; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "❌ Error: jq is required but not installed."; exit 1; }

echo "🔐 Getting Falcon API Token..."

# Get authentication token
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

# Function to discover resources by type
discover_resource_type() {
    local friendly_name=$1
    local resource_type=$2
    local cloud_filter=""

    # Build cloud provider filter
    if [[ "$CLOUD_PROVIDER" != "all" ]]; then
        cloud_filter="cloud_provider%3A%22${CLOUD_PROVIDER}%22%2B"
    fi

    echo ""
    echo "🔍 Discovering: $friendly_name ($resource_type)"
    echo "$(printf '=%.0s' {1..60})"

    # Query for resources
    RESPONSE=$(curl -s -X GET "https://api.crowdstrike.com/cloud-security-assets/queries/resources/v1?filter=${cloud_filter}resource_type%3A%22${resource_type}%22&limit=${LIMIT}" \
      -H "Authorization: Bearer $TOKEN")

    RESOURCE_COUNT=$(echo $RESPONSE | jq '.meta.pagination.total // 0')
    RESOURCE_IDS=$(echo $RESPONSE | jq -r '.resources[]? // empty' | head -n $LIMIT)

    echo "📊 Found $RESOURCE_COUNT total resources"

    if [ "$RESOURCE_COUNT" -gt 0 ] && [ -n "$RESOURCE_IDS" ]; then
        echo ""
        echo "📋 Sample Resource IDs (showing up to $LIMIT):"
        echo "$RESOURCE_IDS" | nl -v1 -w3 -s'. '

        # Get detailed info for first resource to show available fields
        FIRST_ID=$(echo "$RESOURCE_IDS" | head -n 1)
        if [ -n "$FIRST_ID" ]; then
            echo ""
            echo "🔎 Sample Resource Schema (for Rego development):"
            echo "Resource ID: $FIRST_ID"

            DETAILS_RESPONSE=$(curl -s -X GET "https://api.crowdstrike.com/cloud-security-assets/entities/resources/v1?ids=${FIRST_ID}" \
              -H "Authorization: Bearer $TOKEN")

            echo "$DETAILS_RESPONSE" | jq '.resources[0] // empty' > "${friendly_name}_sample_schema.json"

            # Show key fields available for Rego rules
            echo ""
            echo "📝 Key Fields Available for Rego Rules:"
            echo "$DETAILS_RESPONSE" | jq -r '.resources[0] | keys[]' 2>/dev/null | head -20 | sed 's/^/  • /'

            if [[ $(echo "$DETAILS_RESPONSE" | jq '.resources[0].tags // empty' 2>/dev/null) != "null" ]]; then
                echo ""
                echo "🏷️  Available Tags:"
                echo "$DETAILS_RESPONSE" | jq -r '.resources[0].tags | keys[]?' 2>/dev/null | head -10 | sed 's/^/  • /' || echo "  (No tags or tags not accessible)"
            fi

            if [[ $(echo "$DETAILS_RESPONSE" | jq '.resources[0].cloud_context // empty' 2>/dev/null) != "null" ]]; then
                echo ""
                echo "☁️  Cloud Context Fields:"
                echo "$DETAILS_RESPONSE" | jq -r '.resources[0].cloud_context | keys[]?' 2>/dev/null | head -10 | sed 's/^/  • /' || echo "  (No cloud context or not accessible)"
            fi

            echo ""
            echo "💾 Full sample saved to: ${friendly_name}_sample_schema.json"
        fi
    else
        echo "   No resources found for this type"
    fi
}

# Function to show overview of all resources
show_all_resources() {
    echo ""
    echo "📊 Resource Overview for $CLOUD_PROVIDER"
    echo "$(printf '=%.0s' {1..40})"

    local relevant_types=()

    # Filter resource types based on cloud provider
    case $CLOUD_PROVIDER in
        "aws")
            for key in "${!RESOURCE_TYPES[@]}"; do
                if [[ ${RESOURCE_TYPES[$key]} == AWS::* ]] || [[ $key != *azure* && $key != *gcp* ]]; then
                    relevant_types+=("$key")
                fi
            done
            ;;
        "azure")
            for key in "${!RESOURCE_TYPES[@]}"; do
                if [[ ${RESOURCE_TYPES[$key]} == Microsoft.* ]] || [[ $key == azure* ]]; then
                    relevant_types+=("$key")
                fi
            done
            ;;
        "gcp")
            for key in "${!RESOURCE_TYPES[@]}"; do
                if [[ ${RESOURCE_TYPES[$key]} == *.googleapis.com/* ]] || [[ $key == gcp* ]]; then
                    relevant_types+=("$key")
                fi
            done
            ;;
        *)
            relevant_types=(${!RESOURCE_TYPES[@]})
            ;;
    esac

    # Quick count for each resource type
    for resource_key in "${relevant_types[@]}"; do
        resource_type="${RESOURCE_TYPES[$resource_key]}"
        cloud_filter=""

        if [[ "$CLOUD_PROVIDER" != "all" ]]; then
            cloud_filter="cloud_provider%3A%22${CLOUD_PROVIDER}%22%2B"
        fi

        count_response=$(curl -s -X GET "https://api.crowdstrike.com/cloud-security-assets/queries/resources/v1?filter=${cloud_filter}resource_type%3A%22${resource_type}%22&limit=1" \
          -H "Authorization: Bearer $TOKEN")

        count=$(echo $count_response | jq '.meta.pagination.total // 0')
        printf "%-20s %6d resources\n" "$resource_key" "$count"
    done
}

# Main execution
echo "🔍 CrowdStrike Asset Discovery for Custom IOM"
echo "=============================================="
echo "Cloud Provider: $CLOUD_PROVIDER"
echo "Limit: $LIMIT resources per type"
echo ""

if [ "$SHOW_ALL" = true ]; then
    show_all_resources
    echo ""
    echo "💡 To explore a specific resource type:"
    echo "   $0 <resource_type> --limit 20"
    echo ""
    echo "   Example: $0 s3 --limit 20"
elif [ -n "$RESOURCE_TYPE" ]; then
    # Check if resource type exists
    if [[ -n "${RESOURCE_TYPES[$RESOURCE_TYPE]}" ]]; then
        discover_resource_type "$RESOURCE_TYPE" "${RESOURCE_TYPES[$RESOURCE_TYPE]}"
    else
        echo "❌ Error: Unknown resource type '$RESOURCE_TYPE'"
        echo ""
        echo "Use --list-types to see available options"
        exit 1
    fi
else
    echo "❌ Error: No resource type specified"
    echo ""
    show_help
    exit 1
fi

echo ""
echo "🎯 Next Steps:"
echo "1. Review the sample schema JSON file"
echo "2. Identify fields you want to create policies for"
echo "3. Use ./2-analyze-resource-schemas.sh to dive deeper"
echo "4. Create Custom IOM policies with ./3-create-custom-iom.sh"