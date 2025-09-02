#!/bin/bash

# CSPM Policy Report - Super Simple Version
# Just the essentials, no complex jq processing

set -e

# Configuration
BATCH_SIZE=25
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="cspm_policy_summary_${TIMESTAMP}.csv"

# Check environment variables
if [[ -z "$FALCON_CLIENT_ID" || -z "$FALCON_CLIENT_SECRET" ]]; then
    echo "Error: Please set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables"
    exit 1
fi

command -v curl >/dev/null 2>&1 || { echo "Error: curl is required but not installed."; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "Error: jq is required but not installed."; exit 1; }

echo "🔐 Getting bearer token..."

# Get bearer token
BEARER_TOKEN=$(curl \
    --data "client_id=${FALCON_CLIENT_ID}&client_secret=${FALCON_CLIENT_SECRET}" \
    --request POST \
    --silent \
    --fail \
    https://api.crowdstrike.com/oauth2/token | jq -r '.access_token')

if [[ -z "$BEARER_TOKEN" || "$BEARER_TOKEN" == "null" ]]; then
    echo "❌ Failed to get bearer token"
    exit 1
fi

echo "✅ Bearer token retrieved"

# Function to get policy IDs
get_policy_ids() {
    local all_ids=()
    local offset=0
    local limit=500
    
    echo "📋 Getting policy IDs..."
    
    while true; do
        echo "  Fetching batch: offset=$offset"
        
        local response=$(curl \
            --header "Authorization: Bearer ${BEARER_TOKEN}" \
            --request GET \
            --silent \
            --fail \
            "https://api.crowdstrike.com/cloud-policies/queries/rules/v1?limit=${limit}&offset=${offset}")
        
        local batch_ids=($(echo "$response" | jq -r '.resources[]'))
        all_ids+=("${batch_ids[@]}")
        
        local total=$(echo "$response" | jq -r '.meta.pagination.total')
        local returned_count=${#batch_ids[@]}
        
        echo "  Retrieved $returned_count IDs (Total: $total)"
        
        if [[ $returned_count -lt $limit ]]; then
            break
        fi
        
        offset=$((offset + limit))
        
        if [[ $offset -ge $total ]]; then
            break
        fi
    done
    
    echo "✅ Total IDs: ${#all_ids[@]}"
    printf '%s\n' "${all_ids[@]}"
}

# Function to process policies - much simpler approach
process_policies_to_csv() {
    local policy_ids=("$@")
    local total_ids=${#policy_ids[@]}
    local total_batches=$(((total_ids + BATCH_SIZE - 1) / BATCH_SIZE))
    
    echo "📊 Processing $total_ids policies in $total_batches batches..."
    
    # Create CSV header
    echo "Policy ID,Policy Name,Cloud Provider,Resource Type,Service,Description,Alert Logic" > "$OUTPUT_FILE"
    
    for ((i=0; i<$total_ids; i+=$BATCH_SIZE)); do
        local batch_num=$((i/BATCH_SIZE + 1))
        local batch_ids=("${policy_ids[@]:$i:$BATCH_SIZE}")
        local batch_count=${#batch_ids[@]}
        
        echo "🔄 Batch $batch_num/$total_batches ($batch_count policies)"
        
        # Create URL parameters
        local url_params=""
        for id in "${batch_ids[@]}"; do
            if [[ -z "$url_params" ]]; then
                url_params="ids=${id}"
            else
                url_params="${url_params}&ids=${id}"
            fi
        done
        
        # Make API call
        local response=$(curl \
            --header "Authorization: Bearer ${BEARER_TOKEN}" \
            --request GET \
            --silent \
            --fail \
            "https://api.crowdstrike.com/cloud-policies/entities/rules/v1?${url_params}")
        
        # Check if response is valid JSON
        if ! echo "$response" | jq empty 2>/dev/null; then
            echo "   ❌ Invalid JSON response - skipping batch"
            continue
        fi
        
        # Use the simple approach that worked in our test
        echo "$response" | jq -r '.resources[] | 
            .resource_types[] as $rt | 
            [
                .uuid,
                .name,
                .provider,
                $rt.resource_type,
                $rt.service,
                (.description // "" | gsub("\n"; " ") | gsub("\""; "'"'"'")),
                (.alert_info // "" | gsub("\n"; " ") | gsub("\\|"; " - ") | gsub("\""; "'"'"'"))
            ] | @csv' >> "$OUTPUT_FILE"
        
        local returned_count=$(echo "$response" | jq -r '.resources | length // 0')
        echo "   ✅ Processed $returned_count policies"
        
        # Progress
        local percentage=$((batch_num * 100 / total_batches))
        echo "   📊 Progress: $percentage%"
        
        sleep 0.5
    done
}

# Main execution
echo "🚀 CSPM Policy Summary Generator"
echo "================================"

# Get policy IDs
POLICY_IDS=($(get_policy_ids))

# Process to CSV
process_policies_to_csv "${POLICY_IDS[@]}"

# Show results
echo ""
echo "✅ COMPLETE!"
echo "📄 Output file: $OUTPUT_FILE"

# Count rows and show clean stats
if [[ -f "$OUTPUT_FILE" ]]; then
    row_count=$(($(wc -l < "$OUTPUT_FILE") - 1))
    echo "📊 Total rows: $row_count"
    
    if [[ $row_count -gt 0 ]]; then
        echo ""
        echo "📈 Policies by Cloud Provider:"
        # Clean up the provider stats - filter out empty/malformed entries and format nicely
        tail -n +2 "$OUTPUT_FILE" | cut -d',' -f3 | sed 's/"//g' | grep -v '^[[:space:]]*$' | grep -v '^[[:space:]]*[^A-Za-z]' | sort | uniq -c | sort -nr | while read count provider; do
            printf "  %-8s %s\n" "$count" "$provider"
        done
    else
        echo "⚠️  No data was written to the CSV file"
    fi
else
    echo "❌ Output file was not created"
fi

echo ""
echo "💡 To view the full CSV:"
echo "  cat $OUTPUT_FILE"
