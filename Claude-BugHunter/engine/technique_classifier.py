#!/usr/bin/env python3
"""
technique_classifier.py — automatic vulnerability technique classification.

Extracts technique from finding notes/evidence using pattern matching against
known attack patterns learned from disclosed reports and historical findings.
"""

import re
import json
from typing import Optional, Dict, List, Tuple
from pathlib import Path


# Technique pattern database — each entry maps regex → technique
# Patterns ordered by specificity (most specific first)
TECHNIQUE_PATTERNS = {
    # Authorization & Authentication
    "unauth_camunda_traceid": [
        r"camunda.*unauth.*traceId",
        r"camunda.*external.*worker.*no.*auth",
        r"traceId.*minted.*unauth",
        r"internal.*camunda.*published.*unauthenticated"
    ],
    "unauth_mnp_traceid": [
        r"MNP.*unauth.*traceId",
        r"portation.*trace-id.*unauth",
        r"cross-cluster.*traceId.*mnp"
    ],
    "x_ms_trusted_header": [
        r"X-MSISDN.*trusted.*header",
        r"header.*authentication.*msisdn",
        r"subscriber.*data.*via.*header"
    ],
    "session_fixation": [
        r"session.*fixation",
        r"session.*token.*not.*regenerated",
        r"JWT.*not.*invalidated"
    ],
    "auth_bypass_captcha": [
        r"captcha.*bypass",
        r"captcha.*validation.*missing",
        r"otp.*brute.*force.*no.*rate.*limit"
    ],

    # IDOR & Access Control
    "numeric_id_swap": [
        r"IDOR.*\{id\}.*numeric",
        r"numeric.*id.*enumeration",
        r"sequential.*id.*access.*control"
    ],
    "uuid_enumeration": [
        r"UUIDv[14].*enumeration",
        r"time-based.*UUID.*predictable",
        r"MAC.*leaked.*UUID",
        r"request_id.*UUIDv1"
    ],
    "bola_graphql": [
        r"BOLA.*GraphQL",
        r"GraphQL.*IDOR",
        r"graphql.*object.*level.*authorization"
    ],
    "client_side_auth_gate": [
        r"client.*side.*only.*gate",
        r"frontend.*authorization.*check",
        r"render.*flag.*only.*server"
    ],

    # Injection & Code Execution
    "sqli_union_based": [
        r"SQLi.*union.*based",
        r"SQL.*injection.*union.*select"
    ],
    "sqli_error_based": [
        r"SQLi.*error.*based",
        r"SQL.*syntax.*error",
        r"database.*error.*disclosure"
    ],
    "sqli_blind": [
        r"blind.*SQLi",
        r"time-based.*SQL.*injection",
        r"boolean.*based.*SQLi"
    ],
    "xss_reflected": [
        r"reflected.*XSS",
        r"XSS.*via.*parameter",
        r"script.*injected.*response"
    ],
    "xss_stored": [
        r"stored.*XSS",
        r"persistent.*XSS",
        r"XSS.*saved.*profile"
    ],
    "ssti_server_side": [
        r"SSTI.*server.*side",
        r"template.*injection.*\{\{",
        r"Jinja2.*injection"
    ],
    "rce_deserialization": [
        r"RCE.*deserialization",
        r"rO0AB.*deserialization",
        r"Java.*deserialization.*gadget"
    ],

    # SSRF & Network Attacks
    "ssrf_internal_scan": [
        r"SSRF.*internal.*scan",
        r"internal.*port.*scanning",
        r"metadata.*endpoint.*SSRF"
    ],
    "ssrf_cloud_metadata": [
        r"AWS.*metadata.*SSRF",
        r"GCP.*metadata.*SSRF",
        r"169\.254\.169\.254"
    ],

    # Business Logic & Race Conditions
    "business_logic_payment": [
        r"payment.*logic.*bypass",
        r"invoice.*manipulation",
        r"top-up.*unauth"
    ],
    "business_logic_coupon": [
        r"coupon.*abuse",
        r"discount.*stacking",
        r"promo.*code.*bypass"
    ],
    "race_condition": [
        r"race.*condition",
        r"TOCTOU",
        r"concurrent.*request.*bypass"
    ],

    # Information Disclosure
    "info_disclosure_user_listing": [
        r"user.*listing.*unauth",
        r"public.*user.*enumeration",
        r"CTFd.*public.*users"
    ],
    "info_disclosure_private_data": [
        r"private.*data.*exposed",
        r"PII.*leak.*unauth",
        r"sensitive.*information.*disclosure"
    ],
    "source_code_leak": [
        r"\.js\.map.*leaked",
        r"source.*code.*disclosure",
        r"swagger\.json.*exposed"
    ],

    # File Operations
    "file_upload_unauth": [
        r"unauthorized.*file.*upload",
        r"file.*upload.*no.*auth",
        r"arbitrary.*file.*upload"
    ],
    "lfi_path_traversal": [
        r"LFI.*\.\./",
        r"path.*traversal",
        r"file.*inclusion.*local"
    ],

    # Cache & Header Attacks
    "cache_poisoning": [
        r"cache.*poisoning",
        r"web.*cache.*deception",
        r"CDN.*cache.*manipulation"
    ],
    "host_header_injection": [
        r"X-Forwarded-Host.*injection",
        r"Host.*header.*manipulation",
        r"host.*header.*injection"
    ],

    # API & GraphQL
    "graphql_introspection": [
        r"GraphQL.*introspection.*enabled",
        r"__schema.*unauth",
        r"graphql.*schema.*leak"
    ],
    "api_parameter_pollution": [
        r"parameter.*pollution",
        r"parameter.*tampering",
        r"duplicate.*parameter"
    ],

    # Payment & Financial
    "payment_order_manipulation": [
        r"payment.*order.*unauth",
        r"invoice.*generation.*unauth",
        r"payment.*session.*minting"
    ],
    "receipt_disclosure": [
        r"receipt.*exposed.*unauth",
        r"payment.*receipt.*disclosure",
        r"order.*confirmation.*leak"
    ],

    # General Techniques
    "default_credentials": [
        r"default.*credentials",
        r"default.*password",
        r"admin.*admin"
    ],
    "missing_authorization": [
        r"missing.*authorization",
        r"no.*authentication.*required",
        r"unauthenticated.*access"
    ],
    "broken_access_control": [
        r"broken.*access.*control",
        r"authorization.*bypass",
        r"privilege.*escalation"
    ],
}


def extract_technique_from_text(text: str) -> Optional[str]:
    """
    Extract technique from text using pattern matching.
    Returns first matching technique or None.
    """
    if not text or not isinstance(text, str):
        return None

    text_lower = text.lower()

    # Check each technique pattern
    for technique, patterns in TECHNIQUE_PATTERNS.items():
        for pattern in patterns:
            try:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    return technique
            except re.error:
                continue  # Skip invalid regex patterns

    return None


def classify_finding(finding: Dict) -> str:
    """
    Classify a finding's technique from its notes, evidence, and description.
    Returns detected technique or "generic" if no pattern matches.
    """
    # Combine all text fields for classification
    text_parts = []

    for field in ["notes", "evidence", "description", "summary"]:
        if field in finding and finding[field]:
            text_parts.append(str(finding[field]))

    combined_text = " ".join(text_parts)

    # Try to extract technique
    technique = extract_technique_from_text(combined_text)

    return technique if technique else "generic"


def bulk_classify_patterns(patterns_file: Path) -> List[Tuple[str, str]]:
    """
    Bulk classify existing patterns in journal.jsonl or patterns.jsonl.
    Returns list of (entry_id, technique) tuples for entries with null techniques.
    """
    if not patterns_file.exists():
        return []

    results = []
    updated_count = 0

    with open(patterns_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            try:
                entry = json.loads(line)

                # Skip if technique already set and not null
                if entry.get("technique") and entry.get("technique") != "null":
                    continue

                # Classify the finding
                detected = classify_finding(entry)

                if detected != "generic":
                    results.append((line_num, detected, entry))
                    updated_count += 1

            except (json.JSONDecodeError, KeyError):
                continue

    return results


def update_patterns_with_techniques(patterns_file: Path, dry_run: bool = False) -> int:
    """
    Update patterns.jsonl with auto-classified techniques.
    Returns number of entries updated.
    """
    if not patterns_file.exists():
        print(f"Patterns file not found: {patterns_file}")
        return 0

    # Read all entries
    entries = []
    updated_count = 0

    with open(patterns_file, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line)

                # Only update if technique is null or missing
                if not entry.get("technique") or str(entry.get("technique", "")).lower() == "null":
                    detected = classify_finding(entry)
                    if detected != "generic":
                        entry["technique"] = detected
                        updated_count += 1

                entries.append(entry)

            except (json.JSONDecodeError, KeyError):
                entries.append({"raw": line})  # Preserve malformed lines

    if dry_run:
        print(f"Dry run: would update {updated_count} entries")
        return updated_count

    # Write back updated entries
    with open(patterns_file, 'w') as f:
        for entry in entries:
            if "raw" in entry:
                f.write(entry["raw"])
            else:
                f.write(json.dumps(entry) + "\n")

    print(f"Updated {updated_count} entries with techniques")
    return updated_count


def main():
    """CLI interface for technique classification."""
    import argparse

    parser = argparse.ArgumentParser(description="Classify vulnerability techniques")
    parser.add_argument("--patterns", type=Path,
                       default=Path("/opt/Claude/hunt-memory/patterns.jsonl"),
                       help="Path to patterns.jsonl")
    parser.add_argument("--dry-run", action="store_true",
                       help="Show what would be updated without writing")
    parser.add_argument("--stats", action="store_true",
                       help="Show technique statistics")

    args = parser.parse_args()

    if args.stats:
        # Show technique distribution
        technique_counts = {}
        with open(args.patterns, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    technique = entry.get("technique", "null")
                    technique_counts[technique] = technique_counts.get(technique, 0) + 1
                except json.JSONDecodeError:
                    continue

        print("Technique distribution:")
        for technique, count in sorted(technique_counts.items(), key=lambda x: -x[1]):
            print(f"  {technique}: {count}")
    else:
        # Update patterns with techniques
        updated = update_patterns_with_techniques(args.patterns, args.dry_run)

        if not args.dry_run and updated > 0:
            print(f"✓ Classified {updated} findings")


if __name__ == "__main__":
    main()