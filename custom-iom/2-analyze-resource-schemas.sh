#!/bin/bash

# Step 2: Resource Schema Analyzer for Custom IOM Development
# Analyze resource schemas to understand available fields for Rego rule development

set -e

# Configuration
DEFAULT_RESOURCE_TYPE="s3"
OUTPUT_DIR="."

# Help function
show_help() {
    echo "🔬 Resource Schema Analyzer for Custom IOM"
    echo "=========================================="
    echo ""
    echo "This script analyzes resource schemas to help you understand:"
    echo "• Available fields for Rego rule conditions"
    echo "• Data types and structures"
    echo "• Common patterns for policy creation"
    echo ""
    echo "Usage: $0 [OPTIONS] [SCHEMA_FILE]"
    echo ""
    echo "OPTIONS:"
    echo "  -h, --help              Show this help message"
    echo "  -t, --type TYPE         Analyze specific resource type (s3, ec2, iam-users, etc.)"
    echo "  -o, --output DIR        Output directory for analysis files (default: current)"
    echo "  --interactive           Interactive mode - ask questions about fields"
    echo ""
    echo "ARGUMENTS:"
    echo "  SCHEMA_FILE            JSON file from step 1 (e.g., s3_sample_schema.json)"
    echo ""
    echo "EXAMPLES:"
    echo "  $0 s3_sample_schema.json           # Analyze existing schema file"
    echo "  $0 --type s3                       # Fetch and analyze S3 resources"
    echo "  $0 --type ec2 --interactive        # Interactive analysis of EC2"
    echo ""
    echo "WORKFLOW:"
    echo "  1. Run ./1-discover-assets.sh first to get sample schemas"
    echo "  2. Use this script to analyze the fields"
    echo "  3. Use ./3-create-custom-iom.sh to create policies"
}

# Parse command line arguments
RESOURCE_TYPE=""
SCHEMA_FILE=""
INTERACTIVE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -t|--type)
            RESOURCE_TYPE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --interactive)
            INTERACTIVE=true
            shift
            ;;
        *)
            if [[ -z "$SCHEMA_FILE" ]]; then
                SCHEMA_FILE="$1"
            else
                echo "❌ Error: Multiple schema files specified"
                exit 1
            fi
            shift
            ;;
    esac
done

# Check dependencies
command -v jq >/dev/null 2>&1 || { echo "❌ Error: jq is required but not installed."; exit 1; }

# Function to analyze a JSON schema file
analyze_schema_file() {
    local file_path="$1"
    local resource_name=$(basename "$file_path" .json | sed 's/_sample_schema$//')

    if [[ ! -f "$file_path" ]]; then
        echo "❌ Error: Schema file not found: $file_path"
        exit 1
    fi

    echo "🔬 Analyzing Resource Schema: $resource_name"
    echo "$(printf '=%.0s' {1..50})"
    echo "File: $file_path"
    echo ""

    # Basic resource info
    echo "📋 Basic Resource Information:"
    jq -r '
        "  • Resource Type: " + (.resource_type // "unknown"),
        "  • Resource ID: " + (.resource_id // "unknown"),
        "  • Cloud Provider: " + (.cloud_provider // "unknown"),
        "  • Region: " + (.region // "unknown"),
        "  • Active: " + (.active // "unknown" | tostring)
    ' "$file_path"

    echo ""
    echo "🏷️  Available Tags:"
    if jq -e '.tags' "$file_path" >/dev/null 2>&1; then
        jq -r '.tags | keys[]?' "$file_path" 2>/dev/null | head -10 | sed 's/^/  • /' || echo "  (No tags found)"
    else
        echo "  (Tags not available in this resource)"
    fi

    echo ""
    echo "☁️  Cloud Context Fields:"
    if jq -e '.cloud_context' "$file_path" >/dev/null 2>&1; then
        echo "Available for Rego rules as input.cloud_context.*:"
        jq -r '.cloud_context | paths(scalars) as $p | $p | join(".")' "$file_path" 2>/dev/null | head -20 | sed 's/^/  • input.cloud_context./'
    else
        echo "  (Cloud context not available)"
    fi

    echo ""
    echo "🔧 All Available Fields:"
    echo "Available for Rego rules as input.*:"
    jq -r 'paths(scalars) as $p | $p | join(".")' "$file_path" 2>/dev/null | grep -v '^cloud_context\.' | head -20 | sed 's/^/  • input./'

    # Generate Rego rule suggestions
    echo ""
    echo "💡 Suggested Rego Rule Patterns:"
    echo "$(printf '=%.0s' {1..35})"

    # Common patterns based on resource type
    resource_type=$(jq -r '.resource_type // "unknown"' "$file_path")

    case $resource_type in
        "AWS::S3::Bucket")
            generate_s3_suggestions "$file_path"
            ;;
        "AWS::EC2::Instance")
            generate_ec2_suggestions "$file_path"
            ;;
        "AWS::IAM::User")
            generate_iam_suggestions "$file_path"
            ;;
        "AWS::EC2::SecurityGroup")
            generate_sg_suggestions "$file_path"
            ;;
        *)
            generate_generic_suggestions "$file_path"
            ;;
    esac

    # Save analysis to file
    analysis_file="${OUTPUT_DIR}/${resource_name}_analysis.md"
    generate_analysis_report "$file_path" "$resource_name" > "$analysis_file"
    echo ""
    echo "📄 Complete analysis saved to: $analysis_file"

    if [ "$INTERACTIVE" = true ]; then
        interactive_exploration "$file_path"
    fi
}

# Generate S3-specific suggestions
generate_s3_suggestions() {
    local file="$1"
    echo ""
    echo "S3 Bucket Security Patterns:"

    if jq -e '.cloud_context.allows_public_read' "$file" >/dev/null 2>&1; then
        echo '  • Public Access Check:'
        echo '    result := "fail" if input.cloud_context.allows_public_read == true'
    fi

    if jq -e '.cloud_context.encryption' "$file" >/dev/null 2>&1; then
        echo '  • Encryption Requirement:'
        echo '    result := "fail" if input.cloud_context.encryption.enabled == false'
    fi

    if jq -e '.tags' "$file" >/dev/null 2>&1; then
        echo '  • Tag Compliance:'
        echo '    required_tags := ["Environment", "Owner"]'
        echo '    result := "fail" if count([tag | tag := required_tags[_]; input.tags[tag]]) != count(required_tags)'
    fi
}

# Generate EC2-specific suggestions
generate_ec2_suggestions() {
    local file="$1"
    echo ""
    echo "EC2 Instance Compliance Patterns:"

    if jq -e '.cloud_context.instance_type' "$file" >/dev/null 2>&1; then
        echo '  • Instance Type Restrictions:'
        echo '    result := "fail" if startswith(input.cloud_context.instance_type, "t2.")'
    fi

    if jq -e '.cloud_context.security_groups' "$file" >/dev/null 2>&1; then
        echo '  • Security Group Validation:'
        echo '    result := "fail" if count(input.cloud_context.security_groups) > 5'
    fi

    if jq -e '.tags' "$file" >/dev/null 2>&1; then
        echo '  • Required Tagging:'
        echo '    result := "fail" if not input.tags["Environment"]'
    fi
}

# Generate IAM-specific suggestions
generate_iam_suggestions() {
    local file="$1"
    echo ""
    echo "IAM User Security Patterns:"

    if jq -e '.cloud_context.mfa_enabled' "$file" >/dev/null 2>&1; then
        echo '  • MFA Enforcement:'
        echo '    result := "fail" if input.cloud_context.mfa_enabled == false'
    fi

    if jq -e '.cloud_context.access_keys' "$file" >/dev/null 2>&1; then
        echo '  • Access Key Management:'
        echo '    result := "fail" if count(input.cloud_context.access_keys) > 2'
    fi

    echo '  • Service Account Detection:'
    echo '    is_service_account if startswith(input.resource_id, "svc-")'
}

# Generate Security Group suggestions
generate_sg_suggestions() {
    local file="$1"
    echo ""
    echo "Security Group Compliance Patterns:"

    if jq -e '.cloud_context.ingress_rules' "$file" >/dev/null 2>&1; then
        echo '  • Dangerous Port Check:'
        echo '    has_ssh_open if {'
        echo '        rule := input.cloud_context.ingress_rules[_]'
        echo '        rule.port == 22'
        echo '        rule.cidr_blocks[_] == "0.0.0.0/0"'
        echo '    }'
    fi

    echo '  • Description Requirement:'
    echo '    result := "fail" if input.cloud_context.description == ""'
}

# Generate generic suggestions
generate_generic_suggestions() {
    local file="$1"
    echo ""
    echo "Generic Resource Patterns:"

    echo '  • Active Resource Check:'
    echo '    result := "fail" if input.active == false'

    if jq -e '.tags' "$file" >/dev/null 2>&1; then
        echo '  • Basic Tag Requirements:'
        echo '    result := "fail" if not input.tags["Owner"]'
    fi

    echo '  • Region Compliance:'
    echo '    approved_regions := ["us-west-2", "us-east-1"]'
    echo '    result := "fail" if not input.region in approved_regions'
}

# Generate markdown analysis report
generate_analysis_report() {
    local file="$1"
    local resource_name="$2"

    cat << EOF
# Resource Schema Analysis: $resource_name

Generated on: $(date)
Source file: $file

## Resource Overview

$(jq -r '
"**Resource Type:** " + (.resource_type // "unknown") + "  ",
"**Resource ID:** " + (.resource_id // "unknown") + "  ",
"**Cloud Provider:** " + (.cloud_provider // "unknown") + "  ",
"**Region:** " + (.region // "unknown") + "  ",
"**Status:** " + (.active // "unknown" | tostring) + "  "
' "$file")

## Available Fields for Rego Rules

### Basic Fields
EOF

    jq -r 'paths(scalars) as $p | $p | join(".")' "$file" 2>/dev/null | grep -v '^cloud_context\.' | grep -v '^tags\.' | head -10 | sed 's/^/- `input./' | sed 's/$/`/'

    echo ""
    echo "### Tags"
    if jq -e '.tags' "$file" >/dev/null 2>&1; then
        jq -r '.tags | keys[]?' "$file" 2>/dev/null | head -10 | sed 's/^/- `input.tags["/' | sed 's/$/"]`/' || echo "- No tags available"
    else
        echo "- Tags not available"
    fi

    echo ""
    echo "### Cloud Context"
    if jq -e '.cloud_context' "$file" >/dev/null 2>&1; then
        jq -r '.cloud_context | paths(scalars) as $p | $p | join(".")' "$file" 2>/dev/null | head -15 | sed 's/^/- `input.cloud_context./' | sed 's/$/`/'
    else
        echo "- Cloud context not available"
    fi

    echo ""
    echo "## Sample Rego Patterns"
    echo ""
    echo '```rego'
    echo 'package crowdstrike'
    echo ''
    echo 'default result := "fail"'
    echo ''
    echo '# Example: Check if resource is active'
    echo 'result := "pass" if {'
    echo '    input.active == true'
    echo '}'
    echo ''

    if jq -e '.tags' "$file" >/dev/null 2>&1; then
        echo '# Example: Tag validation'
        echo 'result := "pass" if {'
        echo '    input.tags["Environment"]'
        echo '    input.tags["Owner"]'
        echo '}'
        echo ''
    fi

    echo '```'
}

# Interactive exploration
interactive_exploration() {
    local file="$1"

    echo ""
    echo "🤖 Interactive Schema Exploration"
    echo "================================="

    while true; do
        echo ""
        echo "What would you like to explore?"
        echo "1. Show all tag keys"
        echo "2. Show cloud_context structure"
        echo "3. Show specific field value"
        echo "4. Generate sample Rego rule"
        echo "5. Exit interactive mode"
        echo ""
        read -p "Choose (1-5): " choice

        case $choice in
            1)
                echo ""
                echo "🏷️  All available tags:"
                jq -r '.tags | to_entries[] | "  " + .key + " = " + (.value | tostring)' "$file" 2>/dev/null || echo "No tags found"
                ;;
            2)
                echo ""
                echo "☁️  Cloud context structure:"
                jq '.cloud_context' "$file" 2>/dev/null || echo "No cloud context found"
                ;;
            3)
                echo ""
                read -p "Enter field path (e.g., cloud_context.instance_type): " field_path
                echo "Value:"
                jq -r ".$field_path // \"Field not found\"" "$file"
                ;;
            4)
                echo ""
                echo "Generated sample Rego rule:"
                echo '```rego'
                echo 'package crowdstrike'
                echo 'default result := "fail"'
                echo 'result := "pass" if {'
                echo '    input.active == true'
                echo '    # Add your conditions here'
                echo '}'
                echo '```'
                ;;
            5)
                break
                ;;
            *)
                echo "Invalid choice. Please try again."
                ;;
        esac
    done
}

# Main execution
echo "🔬 Resource Schema Analyzer for Custom IOM"
echo "=========================================="

if [[ -n "$SCHEMA_FILE" ]]; then
    # Analyze provided schema file
    analyze_schema_file "$SCHEMA_FILE"
elif [[ -n "$RESOURCE_TYPE" ]]; then
    # Look for existing schema file or suggest running step 1
    schema_file="${RESOURCE_TYPE}_sample_schema.json"
    if [[ -f "$schema_file" ]]; then
        analyze_schema_file "$schema_file"
    else
        echo "❌ Schema file not found: $schema_file"
        echo ""
        echo "💡 First run the asset discovery to generate schema files:"
        echo "   ./1-discover-assets.sh $RESOURCE_TYPE"
        echo ""
        echo "   Then run this script again:"
        echo "   $0 $schema_file"
        exit 1
    fi
else
    echo "❌ Error: No schema file or resource type specified"
    echo ""
    show_help
    exit 1
fi

echo ""
echo "🎯 Next Steps:"
echo "1. Review the analysis and suggested Rego patterns"
echo "2. Customize the patterns for your specific requirements"
echo "3. Use ./3-create-custom-iom.sh to deploy your policies"