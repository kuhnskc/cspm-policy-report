#!/usr/bin/env python3
"""
CSPM Policy Report - IOMs, IOAs, IAC Rules, and Cloud Risks
Generates four separate CSV reports:
  - IOM: Cloud misconfigurations (default + custom)
  - IOA: Behavioral detections (indicators of attack)
  - IAC: Infrastructure-as-code / container / API security rules
  - Cloud Risks: Toxic combinations / cloud security risks
Uses concurrent requests for fast execution.
"""

import csv
import json
import os
import sys
import time
import urllib.request
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

BATCH_SIZE = 100
MAX_WORKERS = 5
BASE_URL = os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com")

PROVIDER_MAP = {"aws": "AWS", "azure": "Azure", "gcp": "GCP", "oci": "OCI"}

CSV_HEADERS = [
    "Policy ID", "Policy Name", "Cloud Provider", "Resource Type", "Service",
    "Origin", "Policy Type", "Description", "Alert Logic", "Remediation Steps",
    "Attack Types",
]

CLOUD_RISK_HEADERS = [
    "Rule ID", "Rule Name", "Severity", "Cloud Provider", "Service Category",
    "Insight Categories", "Risk Factors", "Description", "Finding Count",
    "Open Count", "Resolved Count",
]


def get_bearer_token():
    client_id = os.environ.get("FALCON_CLIENT_ID", "")
    client_secret = os.environ.get("FALCON_CLIENT_SECRET", "")
    if not client_id or not client_secret:
        print("Error: Please set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables")
        sys.exit(1)

    print("🔐 Getting bearer token...")
    data = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": client_secret,
    }).encode()
    req = urllib.request.Request(f"{BASE_URL}/oauth2/token", data=data, method="POST")
    with urllib.request.urlopen(req) as resp:
        token = json.loads(resp.read()).get("access_token")

    if not token:
        print("❌ Failed to get bearer token")
        sys.exit(1)

    print("✅ Bearer token retrieved")
    return token


def api_get(token, path):
    """Make an authenticated GET request and return parsed JSON."""
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        # Strip control characters that break JSON parsing
        cleaned = "".join(c if c == "\n" or c == "\r" or ord(c) >= 32 else " " for c in raw)
        return json.loads(cleaned)


# ──────────────────────────────────────────────
# Settings endpoint (classification + IOAs)
# ──────────────────────────────────────────────

def get_settings_policies(token):
    """Fetch settings/entities/policy/v1. Returns (config_names, ioa_rows)."""
    print("📋 Fetching settings policies for classification...")
    data = api_get(token, "/settings/entities/policy/v1")
    resources = data.get("resources", [])

    # Build set of Configuration policy names — used to classify cloud-policies
    config_names = set()
    ioa_rows = []

    for r in resources:
        ptype = r.get("policy_type", "")
        if ptype == "Configuration":
            config_names.add(r.get("name", ""))
        elif ptype == "Behavioral":
            provider = r.get("cloud_provider", "")
            provider = PROVIDER_MAP.get(provider, provider.upper())
            attack_types = "; ".join(r.get("attack_types") or [])
            ioa_rows.append([
                str(r.get("policy_id", "")),
                r.get("name", ""),
                provider,
                r.get("cloud_asset_type", ""),
                r.get("cloud_service_friendly", ""),
                "Default",
                "IOA",
                "",
                "",
                "",
                attack_types,
            ])

    print(f"✅ Settings: {len(config_names)} Configuration names, {len(ioa_rows)} IOAs")
    return config_names, ioa_rows


# ──────────────────────────────────────────────
# Cloud-policies endpoint (IOMs + IAC)
# ──────────────────────────────────────────────

def get_cloud_policy_ids(token):
    all_ids = []
    offset = 0
    limit = 500
    print("📋 Getting cloud-policy IDs...")

    while True:
        data = api_get(token, f"/cloud-policies/queries/rules/v1?limit={limit}&offset={offset}")
        batch = data.get("resources", [])
        all_ids.extend(batch)
        total = data.get("meta", {}).get("pagination", {}).get("total", 0)
        print(f"  Retrieved {len(batch)} IDs (offset={offset}, total={total})")

        if len(batch) < limit or offset + limit >= total:
            break
        offset += limit

    print(f"✅ Total cloud-policy IDs: {len(all_ids)}")
    return all_ids


def fetch_cloud_policy_batch(token, batch_ids, batch_num, total_batches):
    """Fetch a single batch of cloud-policy details. Returns list of (name, row) tuples."""
    params = "&".join(f"ids={uid}" for uid in batch_ids)
    data = api_get(token, f"/cloud-policies/entities/rules/v1?{params}")
    results = []
    for r in data.get("resources", []):
        name = r.get("name", "")
        for rt in r.get("resource_types", [{}]):
            desc = (r.get("description") or "").replace("\n", " ")
            alert = (r.get("alert_info") or "").replace("\n", " ").replace("|", " - ")
            remed = (r.get("remediation") or "").replace("\n", " ").replace("|", " - ")
            row = [
                r.get("uuid", ""),
                name,
                r.get("provider", ""),
                rt.get("resource_type", ""),
                rt.get("service", ""),
                r.get("origin", "Default"),
                "",  # Policy Type — filled in later during classification
                desc,
                alert,
                remed,
                "",
            ]
            results.append((name, row))
    return batch_num, len(data.get("resources", [])), results


def get_all_cloud_policies(token, policy_ids):
    """Fetch all cloud-policy details concurrently."""
    batches = [policy_ids[i:i + BATCH_SIZE] for i in range(0, len(policy_ids), BATCH_SIZE)]
    total_batches = len(batches)
    all_results = []
    completed = 0

    print(f"📊 Processing {len(policy_ids)} cloud-policies in {total_batches} batches ({MAX_WORKERS} concurrent)...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(fetch_cloud_policy_batch, token, batch, i + 1, total_batches): i
            for i, batch in enumerate(batches)
        }
        for future in as_completed(futures):
            batch_num, count, results = future.result()
            all_results.extend(results)
            completed += 1
            pct = completed * 100 // total_batches
            print(f"  ✅ Batch {completed}/{total_batches} — {pct}%")

    return all_results


# ──────────────────────────────────────────────
# Cloud Risks endpoint (toxic combinations)
# ──────────────────────────────────────────────

def get_cloud_risks(token):
    """Fetch cloud risks and return deduplicated rules as rows."""
    print("📋 Fetching cloud risks...")
    all_findings = []
    offset = 0
    limit = 1000

    while True:
        data = api_get(token, f"/cloud-security-risks/combined/cloud-risks/v1?limit={limit}&offset={offset}")
        batch = data.get("resources", [])
        all_findings.extend(batch)
        total = data.get("meta", {}).get("pagination", {}).get("total", 0)
        print(f"  Retrieved {len(batch)} findings (offset={offset}, total={total})")

        if len(batch) < limit or offset + limit >= total:
            break
        offset += limit

    # Deduplicate by rule_id to get unique rules
    rules = {}
    for r in all_findings:
        rid = r.get("rule_id", "")
        if rid not in rules:
            risk_factor_names = [
                rf.get("insight_name", "") for rf in (r.get("risk_factors") or [])
            ]
            rules[rid] = {
                "rule_id": rid,
                "rule_name": r.get("rule_name", ""),
                "rule_description": (r.get("rule_description") or "").replace("\n", " "),
                "severity": r.get("severity", ""),
                "providers": set(),
                "service_categories": set(),
                "insight_categories": set(),
                "risk_factor_names": risk_factor_names,
                "finding_count": 0,
                "open_count": 0,
                "resolved_count": 0,
            }
        rules[rid]["finding_count"] += 1
        rules[rid]["providers"].add(r.get("provider", ""))
        rules[rid]["service_categories"].add(r.get("service_category", ""))
        for ic in (r.get("insight_categories") or []):
            rules[rid]["insight_categories"].add(ic)
        if r.get("status") == "Open":
            rules[rid]["open_count"] += 1
        else:
            rules[rid]["resolved_count"] += 1

    # Convert to rows
    rows = []
    for info in sorted(rules.values(), key=lambda x: -x["finding_count"]):
        rows.append([
            info["rule_id"],
            info["rule_name"],
            info["severity"],
            "; ".join(sorted(info["providers"])),
            "; ".join(sorted(info["service_categories"])),
            "; ".join(sorted(info["insight_categories"])),
            "; ".join(info["risk_factor_names"]),
            info["rule_description"],
            info["finding_count"],
            info["open_count"],
            info["resolved_count"],
        ])

    print(f"✅ Cloud Risks: {len(all_findings)} findings → {len(rows)} unique rules")
    return rows


def write_csv(filepath, rows, headers=None):
    """Write rows to a CSV file with the given headers."""
    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers or CSV_HEADERS)
        writer.writerows(rows)


def print_breakdown(label, rows, idx):
    """Print a counter breakdown for a column index."""
    counts = Counter(row[idx] for row in rows if row[idx])
    if counts:
        print(f"\n  📈 By {label}:")
        for val, cnt in counts.most_common():
            print(f"    {cnt:<8} {val}")


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────

def main():
    start_time = time.time()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    iom_file = f"cspm_iom_report_{timestamp}.csv"
    ioa_file = f"cspm_ioa_report_{timestamp}.csv"
    iac_file = f"cspm_iac_report_{timestamp}.csv"
    risk_file = f"cspm_cloud_risks_report_{timestamp}.csv"

    print("🚀 CSPM Policy Report — IOMs + IOAs + IAC + Cloud Risks")
    print("=" * 56)

    token = get_bearer_token()

    # Step 1: Fetch settings policies (for classification + IOAs)
    config_names, ioa_rows = get_settings_policies(token)

    print()
    print("─" * 38)
    print()

    # Step 2: Fetch all cloud-policies
    cp_ids = get_cloud_policy_ids(token)
    cp_results = get_all_cloud_policies(token, cp_ids)

    # Step 3: Classify cloud-policies into IOM vs IAC
    iom_rows = []
    iac_rows = []
    for name, row in cp_results:
        if name in config_names:
            row[6] = "IOM"
            iom_rows.append(row)
        else:
            row[6] = "IAC"
            iac_rows.append(row)

    # Step 4: Fetch cloud risks (toxic combinations)
    print()
    print("─" * 38)
    print()
    risk_rows = get_cloud_risks(token)

    # Step 5: Write CSVs
    write_csv(iom_file, iom_rows)
    write_csv(ioa_file, ioa_rows)
    write_csv(iac_file, iac_rows)
    write_csv(risk_file, risk_rows, headers=CLOUD_RISK_HEADERS)

    elapsed = time.time() - start_time

    # Summary
    print()
    print("✅ COMPLETE!")
    print(f"⏱️  Completed in {elapsed:.1f}s")
    print()

    for label, filepath, rows in [
        ("IOM (Cloud Misconfigurations)", iom_file, iom_rows),
        ("IOA (Behavioral Detections)", ioa_file, ioa_rows),
        ("IAC (Infrastructure-as-Code)", iac_file, iac_rows),
    ]:
        print(f"📄 {label}: {filepath} ({len(rows)} rows)")
        print_breakdown("Cloud Provider", rows, 2)
        print_breakdown("Origin", rows, 5)
        print()

    print(f"📄 Cloud Risks (Toxic Combinations): {risk_file} ({len(risk_rows)} rules)")
    print_breakdown("Severity", risk_rows, 2)
    print_breakdown("Service Category", risk_rows, 4)
    print()

    total = len(iom_rows) + len(ioa_rows) + len(iac_rows) + len(risk_rows)
    print(f"📊 Total across all reports: {total}")


if __name__ == "__main__":
    main()
