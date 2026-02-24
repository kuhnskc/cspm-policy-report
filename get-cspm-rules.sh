#!/bin/bash

# CSPM Policy Report - IOMs, IOAs, IAC Rules, and Cloud Risks
# Generates four separate CSV reports:
#   - IOM: Cloud misconfigurations (default + custom)
#   - IOA: Behavioral detections (indicators of attack)
#   - IAC: Infrastructure-as-code / container / API security rules
#   - Cloud Risks: Toxic combinations / cloud security risks

set -e

# Configuration
BATCH_SIZE=25
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
IOM_FILE="cspm_iom_report_${TIMESTAMP}.csv"
IOA_FILE="cspm_ioa_report_${TIMESTAMP}.csv"
IAC_FILE="cspm_iac_report_${TIMESTAMP}.csv"
RISK_FILE="cspm_cloud_risks_report_${TIMESTAMP}.csv"
CSV_HEADER="Policy ID,Policy Name,Cloud Provider,Resource Type,Service,Origin,Policy Type,Description,Alert Logic,Remediation Steps,Attack Types"
RISK_CSV_HEADER="Rule ID,Rule Name,Severity,Cloud Provider,Service Category,Insight Categories,Risk Factors,Description,Finding Count,Open Count,Resolved Count"
BASE_URL="${FALCON_BASE_URL:-https://api.crowdstrike.com}"

# Temp file for settings Configuration names (used for classification)
CONFIG_NAMES_FILE=$(mktemp)
trap "rm -f $CONFIG_NAMES_FILE" EXIT

# Check environment variables
if [[ -z "$FALCON_CLIENT_ID" || -z "$FALCON_CLIENT_SECRET" ]]; then
    echo "Error: Please set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables"
    exit 1
fi

command -v curl >/dev/null 2>&1 || { echo "Error: curl is required but not installed."; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "Error: jq is required but not installed."; exit 1; }

echo "🔐 Getting bearer token..."

BEARER_TOKEN=$(curl \
    --data "client_id=${FALCON_CLIENT_ID}&client_secret=${FALCON_CLIENT_SECRET}" \
    --request POST \
    --silent \
    --fail \
    "${BASE_URL}/oauth2/token" | jq -r '.access_token')

if [[ -z "$BEARER_TOKEN" || "$BEARER_TOKEN" == "null" ]]; then
    echo "❌ Failed to get bearer token"
    exit 1
fi

echo "✅ Bearer token retrieved"

# ──────────────────────────────────────────────
# SECTION 1: Settings (classification + IOAs)
# ──────────────────────────────────────────────

echo "📋 Fetching settings policies for classification..."

SETTINGS_RESPONSE=$(curl \
    --header "Authorization: Bearer ${BEARER_TOKEN}" \
    --request GET \
    --silent \
    --fail \
    "${BASE_URL}/settings/entities/policy/v1")

# Extract Configuration names for classification
echo "$SETTINGS_RESPONSE" | jq -r '[.resources[] | select(.policy_type == "Configuration")] | .[].name' > "$CONFIG_NAMES_FILE"
CONFIG_COUNT=$(wc -l < "$CONFIG_NAMES_FILE" | tr -d ' ')
echo "✅ Settings: $CONFIG_COUNT Configuration names loaded"

# Write IOA CSV
echo "$CSV_HEADER" > "$IOA_FILE"
IOA_COUNT=$(echo "$SETTINGS_RESPONSE" | jq '[.resources[] | select(.policy_type == "Behavioral")] | length')
echo "✅ Found $IOA_COUNT IOA policies"

echo "$SETTINGS_RESPONSE" | jq -r '
    [.resources[] | select(.policy_type == "Behavioral")] | .[] |
    [
        (.policy_id | tostring),
        .name,
        (.cloud_provider // "" | if . == "aws" then "AWS" elif . == "azure" then "Azure" elif . == "gcp" then "GCP" elif . == "oci" then "OCI" else ascii_upcase end),
        (.cloud_asset_type // ""),
        (.cloud_service_friendly // ""),
        "Default",
        "IOA",
        "",
        "",
        "",
        ((.attack_types // []) | join("; "))
    ] | @csv' >> "$IOA_FILE"

echo "   ✅ Processed $IOA_COUNT IOAs"

# ──────────────────────────────────────────────
# SECTION 2: Cloud-policies (IOMs + IAC)
# ──────────────────────────────────────────────

get_cloud_policy_ids() {
    local all_ids=()
    local offset=0
    local limit=500

    echo "📋 Getting cloud-policy IDs..."

    while true; do
        echo "  Fetching batch: offset=$offset"

        local response=$(curl \
            --header "Authorization: Bearer ${BEARER_TOKEN}" \
            --request GET \
            --silent \
            --fail \
            "${BASE_URL}/cloud-policies/queries/rules/v1?limit=${limit}&offset=${offset}")

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

    echo "✅ Total cloud-policy IDs: ${#all_ids[@]}"
    printf '%s\n' "${all_ids[@]}"
}

process_cloud_policies() {
    local policy_ids=("$@")
    local total_ids=${#policy_ids[@]}
    local total_batches=$(((total_ids + BATCH_SIZE - 1) / BATCH_SIZE))

    echo "📊 Processing $total_ids cloud-policies in $total_batches batches..."

    # Initialize CSV files
    echo "$CSV_HEADER" > "$IOM_FILE"
    echo "$CSV_HEADER" > "$IAC_FILE"

    for ((i=0; i<$total_ids; i+=$BATCH_SIZE)); do
        local batch_num=$((i/BATCH_SIZE + 1))
        local batch_ids=("${policy_ids[@]:$i:$BATCH_SIZE}")
        local batch_count=${#batch_ids[@]}

        echo "🔄 Batch $batch_num/$total_batches ($batch_count policies)"

        local url_params=""
        for id in "${batch_ids[@]}"; do
            if [[ -z "$url_params" ]]; then
                url_params="ids=${id}"
            else
                url_params="${url_params}&ids=${id}"
            fi
        done

        local response=$(curl \
            --header "Authorization: Bearer ${BEARER_TOKEN}" \
            --request GET \
            --silent \
            --fail \
            "${BASE_URL}/cloud-policies/entities/rules/v1?${url_params}")

        if ! echo "$response" | jq empty 2>/dev/null; then
            echo "   ❌ Invalid JSON response - skipping batch"
            continue
        fi

        # Classify each policy: name in config names → IOM, else → IAC
        # Use python for reliable name matching against the config names file
        echo "$response" | python3 -c "
import csv, json, sys, io

config_names = set()
with open('$CONFIG_NAMES_FILE') as f:
    for line in f:
        config_names.add(line.strip())

data = json.load(sys.stdin)
iom_out = io.StringIO()
iac_out = io.StringIO()
iom_writer = csv.writer(iom_out)
iac_writer = csv.writer(iac_out)

for r in data.get('resources', []):
    name = r.get('name', '')
    for rt in r.get('resource_types', [{}]):
        desc = (r.get('description') or '').replace('\n', ' ')
        alert = (r.get('alert_info') or '').replace('\n', ' ').replace('|', ' - ')
        remed = (r.get('remediation') or '').replace('\n', ' ').replace('|', ' - ')
        ptype = 'IOM' if name in config_names else 'IAC'
        row = [
            r.get('uuid', ''),
            name,
            r.get('provider', ''),
            rt.get('resource_type', ''),
            rt.get('service', ''),
            r.get('origin', 'Default'),
            ptype,
            desc, alert, remed, '',
        ]
        if ptype == 'IOM':
            iom_writer.writerow(row)
        else:
            iac_writer.writerow(row)

iom_text = iom_out.getvalue()
iac_text = iac_out.getvalue()
if iom_text:
    sys.stdout.write('IOM:' + iom_text)
if iac_text:
    sys.stdout.write('IAC:' + iac_text)
" | while IFS= read -r line; do
            if [[ "$line" == IOM:* ]]; then
                echo "${line#IOM:}" >> "$IOM_FILE"
            elif [[ "$line" == IAC:* ]]; then
                echo "${line#IAC:}" >> "$IAC_FILE"
            else
                echo "$line" >> "$IOM_FILE"
            fi
        done

        local returned_count=$(echo "$response" | jq -r '.resources | length // 0')
        echo "   ✅ Processed $returned_count policies"

        local percentage=$((batch_num * 100 / total_batches))
        echo "   📊 Progress: $percentage%"

        sleep 0.5
    done
}

# ──────────────────────────────────────────────
# Main execution
# ──────────────────────────────────────────────

echo ""
echo "🚀 CSPM Policy Report — IOMs + IOAs + IAC + Cloud Risks"
echo "===================================================="
echo ""

# Get and process cloud-policies (IOMs + IAC)
CP_IDS=($(get_cloud_policy_ids))
process_cloud_policies "${CP_IDS[@]}"

# ──────────────────────────────────────────────
# SECTION 3: Cloud Risks (toxic combinations)
# ──────────────────────────────────────────────

echo ""
echo "📋 Fetching cloud risks..."

echo "$RISK_CSV_HEADER" > "$RISK_FILE"

# Fetch all cloud risk findings with pagination, then deduplicate by rule_id
RISK_FINDINGS=""
RISK_OFFSET=0
RISK_LIMIT=1000

while true; do
    RISK_RESPONSE=$(curl \
        --header "Authorization: Bearer ${BEARER_TOKEN}" \
        --request GET \
        --silent \
        --fail \
        "${BASE_URL}/cloud-security-risks/combined/cloud-risks/v1?limit=${RISK_LIMIT}&offset=${RISK_OFFSET}")

    RISK_BATCH_COUNT=$(echo "$RISK_RESPONSE" | jq -r '.resources | length')
    RISK_TOTAL=$(echo "$RISK_RESPONSE" | jq -r '.meta.pagination.total')

    echo "  Retrieved $RISK_BATCH_COUNT findings (offset=$RISK_OFFSET, total=$RISK_TOTAL)"

    if [[ -z "$RISK_FINDINGS" ]]; then
        RISK_FINDINGS="$RISK_RESPONSE"
    else
        # Merge resources arrays
        RISK_FINDINGS=$(echo "$RISK_FINDINGS" "$RISK_RESPONSE" | jq -s '.[0].resources += .[1].resources | .[0]')
    fi

    if [[ $RISK_BATCH_COUNT -lt $RISK_LIMIT ]] || [[ $((RISK_OFFSET + RISK_LIMIT)) -ge $RISK_TOTAL ]]; then
        break
    fi

    RISK_OFFSET=$((RISK_OFFSET + RISK_LIMIT))
done

# Deduplicate by rule_id and write CSV using python
echo "$RISK_FINDINGS" | python3 -c "
import csv, json, sys, io

data = json.load(sys.stdin)
findings = data.get('resources', [])

rules = {}
for r in findings:
    rid = r.get('rule_id', '')
    if rid not in rules:
        risk_factor_names = [
            rf.get('insight_name', '') for rf in (r.get('risk_factors') or [])
        ]
        rules[rid] = {
            'rule_id': rid,
            'rule_name': r.get('rule_name', ''),
            'rule_description': (r.get('rule_description') or '').replace('\n', ' '),
            'severity': r.get('severity', ''),
            'providers': set(),
            'service_categories': set(),
            'insight_categories': set(),
            'risk_factor_names': risk_factor_names,
            'finding_count': 0,
            'open_count': 0,
            'resolved_count': 0,
        }
    rules[rid]['finding_count'] += 1
    rules[rid]['providers'].add(r.get('provider', ''))
    rules[rid]['service_categories'].add(r.get('service_category', ''))
    for ic in (r.get('insight_categories') or []):
        rules[rid]['insight_categories'].add(ic)
    if r.get('status') == 'Open':
        rules[rid]['open_count'] += 1
    else:
        rules[rid]['resolved_count'] += 1

out = io.StringIO()
writer = csv.writer(out)
for info in sorted(rules.values(), key=lambda x: -x['finding_count']):
    writer.writerow([
        info['rule_id'],
        info['rule_name'],
        info['severity'],
        '; '.join(sorted(info['providers'])),
        '; '.join(sorted(info['service_categories'])),
        '; '.join(sorted(info['insight_categories'])),
        '; '.join(info['risk_factor_names']),
        info['rule_description'],
        info['finding_count'],
        info['open_count'],
        info['resolved_count'],
    ])

sys.stdout.write(out.getvalue())
print(f'{len(findings)} findings -> {len(rules)} unique rules', file=sys.stderr)
" >> "$RISK_FILE"

# ──────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────

echo ""
echo "✅ COMPLETE!"

python3 -c "
import csv, collections

for label, filepath in [
    ('IOM (Cloud Misconfigurations)', '$IOM_FILE'),
    ('IOA (Behavioral Detections)', '$IOA_FILE'),
    ('IAC (Infrastructure-as-Code)', '$IAC_FILE'),
]:
    with open(filepath) as f:
        rows = list(csv.DictReader(f))
    print(f'\n📄 {label}: {filepath} ({len(rows)} rows)')
    for col_label, key in [('Cloud Provider', 'Cloud Provider'), ('Origin', 'Origin')]:
        counts = collections.Counter(r[key] for r in rows if r.get(key))
        if counts:
            print(f'\n  📈 By {col_label}:')
            for val, cnt in counts.most_common():
                print(f'    {cnt:<8} {val}')

# Cloud Risks report
with open('$RISK_FILE') as f:
    risk_rows = list(csv.DictReader(f))
print(f'\n📄 Cloud Risks (Toxic Combinations): $RISK_FILE ({len(risk_rows)} rules)')
for col_label, key in [('Severity', 'Severity'), ('Service Category', 'Service Category')]:
    counts = collections.Counter(r[key] for r in risk_rows if r.get(key))
    if counts:
        print(f'\n  📈 By {col_label}:')
        for val, cnt in counts.most_common():
            print(f'    {cnt:<8} {val}')

total = sum(
    sum(1 for _ in csv.DictReader(open(f)))
    for f in ['$IOM_FILE', '$IOA_FILE', '$IAC_FILE', '$RISK_FILE']
)
print(f'\n📊 Total across all reports: {total}')
"
