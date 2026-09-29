#!/usr/bin/env python3
"""
pattern-analytics.py — hunt memory analytics engine.

Extracts actionable intelligence from accumulated patterns:
- Which techniques work on which tech stacks
- Success rate by technique/stack/severity
- Payout distribution and expected value
- Target prioritization recommendations
"""

import json
import re
import argparse
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict, Counter
import sys

ENGINE_DIR = Path(__file__).resolve().parent.parent / "engine"
sys.path.insert(0, str(ENGINE_DIR))
try:
    from memory import normalize_technique, normalize_vuln_class
except ImportError:  # standalone fallback
    normalize_technique = lambda value: str(value or "generic")  # noqa: E731
    normalize_vuln_class = lambda value: str(value or "unspecified")  # noqa: E731


def outcome(pattern: Dict, default: str = "confirmed") -> str:
    """Normalize old success-only pattern rows and the new explicit outcomes.

    `default` matters: patterns.jsonl is success-only by construction, so a row with
    no `result` there really was confirmed. A journal row with no result is an
    unknown attempt, and assuming success would reintroduce the 100%-success-rate
    bug from the other end.
    """
    value = str(pattern.get("triage_outcome") or pattern.get("result") or "").lower()
    return value or default


CONFIRMED_OUTCOMES = {"confirmed", "submitted", "accepted", "paid", "duplicate", "downgraded"}
ACCEPTED_OUTCOMES = {"accepted", "paid"}
# Platform verdicts are tracked separately from local technical confirmation: a
# technique can reproduce perfectly and still be closed N/A, and conflating the two
# is how a 100%-success technique list gets built out of rejected work.
PLATFORM_OUTCOMES = {"submitted", "accepted", "paid", "na", "downgraded", "duplicate"}


def locally_confirmed(pattern: Dict, default: str = "confirmed") -> bool:
    return bool(pattern.get("locally_confirmed")) or outcome(pattern, default) in CONFIRMED_OUTCOMES


def triage_accepted(pattern: Dict, default: str = "confirmed") -> bool:
    return outcome(pattern, default) in ACCEPTED_OUTCOMES


def load_attempts(journal_file: Path, patterns: List[Dict]) -> Tuple[List[Dict], str]:
    """The denominator corpus for every rate this script prints.

    patterns.jsonl holds confirmed rows only, so `confirmed / len(patterns)` is 100%
    by construction — a number that looks like evidence and carries none. journal.jsonl
    is the real attempt log (rejected rows included), so it is the denominator whenever
    it exists; patterns.jsonl stays the fallback for a corpus that predates it, and the
    caller is told which one it got.
    """
    journal = load_patterns(journal_file)
    if journal:
        return journal, "journal"
    return patterns, "patterns"


def load_patterns(patterns_file: Path) -> List[Dict]:
    """Load patterns from JSONL file."""
    patterns = []
    if not patterns_file.exists():
        return patterns

    with open(patterns_file, 'r') as f:
        for line in f:
            try:
                patterns.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return patterns


def normalize_tech_stack(tech_stack: List[str]) -> Tuple[List[str], str]:
    """
    Normalize and extract key tech components.
    Returns (normalized_list, primary_stack).
    """
    if not tech_stack:
        return [], "unknown"

    # Normalize tech names
    normalized = []
    for tech in tech_stack:
        tech_lower = tech.lower().strip()

        # Map variations to standard names
        if "next" in tech_lower and "js" in tech_lower:
            normalized.append("next.js")
        elif "react" in tech_lower:
            normalized.append("react")
        elif "vue" in tech_lower:
            normalized.append("vue")
        elif "angular" in tech_lower:
            normalized.append("angular")
        elif "express" in tech_lower:
            normalized.append("express")
        elif "fastapi" in tech_lower:
            normalized.append("fastapi")
        elif "flask" in tech_lower:
            normalized.append("flask")
        elif "django" in tech_lower:
            normalized.append("django")
        elif "laravel" in tech_lower:
            normalized.append("laravel")
        elif "spring" in tech_lower:
            normalized.append("spring-boot")
        elif "asp" in tech_lower or ".net" in tech_lower:
            normalized.append("asp.net")
        elif "sharepoint" in tech_lower:
            normalized.append("sharepoint")
        elif "graphql" in tech_lower:
            normalized.append("graphql")
        elif "grpc" in tech_lower:
            normalized.append("grpc")
        elif "node" in tech_lower:
            normalized.append("node.js")
        elif "python" in tech_lower:
            normalized.append("python")
        else:
            # Use as-is if no mapping
            normalized.append(tech)

    # Determine primary stack (framework/backend)
    primary = "unknown"
    for tech in normalized:
        if tech in ["next.js", "react", "vue", "angular"]:
            primary = tech
            break
        elif tech in ["express", "fastapi", "flask", "django", "spring-boot", "asp.net", "node.js", "python"]:
            primary = tech
            break
        elif tech in ["laravel", "sharepoint", "graphql"]:
            primary = tech
            break

    return normalized, primary


def analyze_techniques_by_stack(patterns: List[Dict], stack_filter: str = None,
                                source: str = "patterns") -> Dict:
    """
    Analyze which techniques work on which stacks.
    Returns nested dict: stack -> technique -> stats.

    `patterns` is the ATTEMPT corpus — pass journal.jsonl rows here (source="journal")
    so `success_rate` divides confirmations by everything that was tried. Passing the
    success-only patterns.jsonl yields 100% for every technique, which is why the
    corpus kind is named in the output.
    """
    default_outcome = "confirmed" if source == "patterns" else "unknown"
    stack_stats = defaultdict(lambda: defaultdict(lambda: {
        "count": 0,
        "confirmed": 0,
        "accepted": 0,
        "platform_judged": 0,
        "total_payout": 0,
        "severities": Counter(),
        "targets": set()
    }))

    for pattern in patterns:
        # Normalize tech stack
        tech_list = pattern.get("tech_stack", [])
        normalized, primary = normalize_tech_stack(tech_list)

        # Apply stack filter if specified
        if stack_filter and stack_filter.lower() not in [t.lower() for t in normalized]:
            continue

        # Use primary stack as key, fallback to first component
        stack_key = primary if primary != "unknown" else (normalized[0] if normalized else "unknown")

        # Extract technique
        technique = normalize_technique(pattern.get("technique"))
        severity = pattern.get("severity", "")
        payout = pattern.get("payout", 0)
        target = pattern.get("target", "")

        # Update stats
        stats = stack_stats[stack_key][technique]
        stats["count"] += 1
        stats["targets"].add(target)

        if locally_confirmed(pattern, default_outcome):
            stats["confirmed"] += 1
            stats["total_payout"] += payout
        if outcome(pattern, default_outcome) in PLATFORM_OUTCOMES:
            stats["platform_judged"] += 1
        if triage_accepted(pattern, default_outcome):
            stats["accepted"] += 1

        if severity:
            stats["severities"][severity] += 1

    # Convert sets to counts for serialization
    result = {}
    for stack, techniques in stack_stats.items():
        result[stack] = {}
        for tech, stats in techniques.items():
            result[stack][tech] = {
                "attempts": stats["count"],
                "count": stats["count"],          # kept: older callers read `count`
                "confirmed": stats["confirmed"],
                "accepted": stats["accepted"],
                "platform_judged": stats["platform_judged"],
                "success_rate": round(stats["confirmed"] / stats["count"] * 100, 1) if stats["count"] > 0 else 0,
                # What triage did with it, out of the ones triage actually saw. A
                # technique that reproduces every time and gets closed N/A every time
                # is not a technique worth repeating, and only this number says so.
                "accepted_rate": (round(stats["accepted"] / stats["platform_judged"] * 100, 1)
                                  if stats["platform_judged"] > 0 else None),
                "total_payout": stats["total_payout"],
                "avg_payout": round(stats["total_payout"] / stats["confirmed"], 2) if stats["confirmed"] > 0 else 0,
                "severities": dict(stats["severities"]),
                "unique_targets": len(stats["targets"]),
                "denominator": source,
            }

    return result


def get_priority_targets(patterns: List[Dict], source: str = "patterns") -> List[Tuple[str, Dict]]:
    """
    Rank targets by vulnerability density and payout potential.
    Returns list of (target, stats) tuples sorted by priority.
    """
    default_outcome = "confirmed" if source == "patterns" else "unknown"
    target_stats = defaultdict(lambda: {
        "findings": 0,
        "confirmed": 0,
        "total_payout": 0,
        "techniques": set(),
        "severities": Counter(),
        "tech_stacks": []
    })

    for pattern in patterns:
        target = pattern.get("target", "")
        if not target:
            continue

        stats = target_stats[target]
        stats["findings"] += 1

        if locally_confirmed(pattern, default_outcome):
            stats["confirmed"] += 1
            stats["total_payout"] += pattern.get("payout", 0)

        technique = normalize_technique(pattern.get("technique"))
        if technique:
            stats["techniques"].add(technique)

        severity = pattern.get("severity", "")
        if severity:
            stats["severities"][severity] += 1

        # Collect unique tech stacks
        tech_stack = pattern.get("tech_stack", [])
        if tech_stack and tech_stack not in stats["tech_stacks"]:
            stats["tech_stacks"].append(tech_stack)

    # Convert to list and sort by priority
    target_list = []
    for target, stats in target_stats.items():
        if stats["findings"] == 0:
            continue

        # A free-form technique label must never raise a target's priority.  Rank
        # with evidence and realized value; diversity remains display-only.
        accepted = sum(1 for p in patterns
                       if p.get("target") == target and triage_accepted(p, default_outcome))
        priority_score = stats["confirmed"] * 3 + accepted * 12 + stats["total_payout"] / 1000

        target_list.append((target, {
            **stats,
            "techniques": list(stats["techniques"]),
            "accepted": accepted,
            "priority_score": round(priority_score, 2)
        }))

    # Sort by priority score descending
    target_list.sort(key=lambda x: x[1]["priority_score"], reverse=True)

    return target_list


def get_recommendations(stack_stats: Dict, target_stack: str = None) -> List[str]:
    """
    Generate hunting recommendations based on historical success.
    """
    recommendations = []

    if target_stack:
        # Target-specific recommendations
        if target_stack in stack_stats:
            techniques = stack_stats[target_stack]

            # Find top techniques by success rate
            sorted_techniques = sorted(
                techniques.items(),
                key=lambda x: (x[1]["success_rate"], x[1]["avg_payout"]),
                reverse=True
            )[:5]

            if sorted_techniques:
                recommendations.append(f"Top techniques for {target_stack}:")
                for tech, stats in sorted_techniques:
                    if stats["confirmed"] > 0:
                        recommendations.append(
                            f"  - {tech}: {stats['success_rate']}% success, "
                            f"avg ${stats['avg_payout']}, {stats['confirmed']} confirmed"
                        )

        # Check if similar stacks have data
        similar_stacks = [s for s in stack_stats.keys()
                          if target_stack.lower() in s.lower() or s.lower() in target_stack.lower()]

        for similar in similar_stacks:
            if similar == target_stack:
                continue
            techniques = stack_stats[similar]
            top_technique = max(techniques.items(), key=lambda x: x[1]["success_rate"])
            if top_technique[1]["confirmed"] > 0:
                recommendations.append(
                    f"Similar stack {similar} suggests: {top_technique[0]} "
                    f"({top_technique[1]['success_rate']}% success)"
                )
    else:
        # General high-value techniques across all stacks
        all_techniques = defaultdict(lambda: {
            "confirmed": 0,
            "total": 0,
            "total_payout": 0
        })

        for stack, techniques in stack_stats.items():
            for tech, stats in techniques.items():
                all_techniques[tech]["confirmed"] += stats["confirmed"]
                all_techniques[tech]["total"] += stats["count"]
                all_techniques[tech]["total_payout"] += stats["total_payout"]

        # Top 5 techniques by overall success
        sorted_techniques = sorted(
            all_techniques.items(),
            key=lambda x: (x[1]["confirmed"] / x[1]["total"] if x[1]["total"] > 0 else 0,
                         x[1]["total_payout"]),
            reverse=True
        )[:5]

        if sorted_techniques:
            recommendations.append("Top techniques across all stacks:")
            for tech, stats in sorted_techniques:
                if stats["confirmed"] > 0:
                    success_rate = round(stats["confirmed"] / stats["total"] * 100, 1)
                    avg_payout = round(stats["total_payout"] / stats["confirmed"], 2)
                    recommendations.append(
                        f"  - {tech}: {success_rate}% success, avg ${avg_payout}, "
                        f"{stats['confirmed']}/{stats['total']} confirmed"
                    )

    return recommendations


def main():
    parser = argparse.ArgumentParser(description="Hunt memory analytics")
    parser.add_argument("--patterns", type=Path,
                       default=Path("/opt/Claude/hunt-memory/patterns.jsonl"),
                       help="Path to patterns.jsonl (confirmed rows — payout/severity detail)")
    parser.add_argument("--journal", type=Path, default=None,
                       help="Path to journal.jsonl (every attempt — the rate denominator; "
                            "defaults to journal.jsonl beside --patterns)")
    parser.add_argument("--stack", type=str,
                       help="Filter by tech stack (e.g., 'next.js', 'react')")
    parser.add_argument("--min-payout", type=int,
                       help="Filter techniques by minimum average payout")
    parser.add_argument("--top-targets", type=int, default=10,
                       help="Number of top targets to show")
    parser.add_argument("--recommendations", action="store_true",
                       help="Show hunting recommendations")
    parser.add_argument("--format", type=str, choices=["text", "json"], default="text",
                       help="Output format")

    args = parser.parse_args()

    # Load patterns + the attempt corpus behind every rate below
    patterns = load_patterns(args.patterns)
    journal_file = args.journal or args.patterns.with_name("journal.jsonl")
    attempts, source = load_attempts(journal_file, patterns)

    if not attempts:
        print("No patterns found.")
        return

    print(f"Loaded {len(patterns)} pattern(s) from {args.patterns}")
    if source == "journal":
        print(f"Rates computed over {len(attempts)} attempt(s) from {journal_file}")
    else:
        print(f"WARNING: no journal at {journal_file} — rates fall back to the "
              f"confirmed-only patterns file and will read ~100%. Log rejections with "
              f"`/remember --result rejected` to make these numbers mean something.")
    print()

    # Analyze techniques by stack
    stack_stats = analyze_techniques_by_stack(attempts, args.stack, source)

    if args.format == "json":
        # Output JSON format
        output = {
            "patterns_analyzed": len(patterns),
            "attempts_analyzed": len(attempts),
            "denominator": source,
            "stack_stats": stack_stats,
            "priority_targets": get_priority_targets(attempts, source)[:args.top_targets]
        }

        if args.recommendations:
            output["recommendations"] = get_recommendations(stack_stats, args.stack)

        print(json.dumps(output, indent=2))
        return

    # Text format output
    print("=== TECHNIQUES BY STACK ===")
    for stack in sorted(stack_stats.keys()):
        techniques = stack_stats[stack]
        print(f"\n{stack.upper()}:")

        # Sort by success rate, then avg payout
        sorted_techniques = sorted(
            techniques.items(),
            key=lambda x: (x[1]["success_rate"], x[1]["avg_payout"]),
            reverse=True
        )

        for tech, stats in sorted_techniques:
            if args.min_payout and stats["avg_payout"] < args.min_payout:
                continue

            success_rate = stats["success_rate"]
            confirmed = stats["confirmed"]
            total = stats["count"]
            avg_payout = stats["avg_payout"]

            if confirmed > 0:
                line = (f"  {tech}: {success_rate}% ({confirmed}/{total} confirmed), "
                        f"avg ${avg_payout}, {stats['unique_targets']} targets")
                if stats.get("accepted_rate") is not None:
                    line += (f" | triage: {stats['accepted_rate']}% accepted "
                             f"({stats['accepted']}/{stats['platform_judged']})")
                print(line)

                # Show severity breakdown
                if stats["severities"]:
                    severity_str = ", ".join([f"{s}:{c}" for s, c in sorted(stats["severities"].items())])
                    print(f"      Severities: {severity_str}")

    # Show priority targets
    print(f"\n=== TOP {args.top_targets} PRIORITY TARGETS ===")
    priority_targets = get_priority_targets(attempts, source)[:args.top_targets]

    for i, (target, stats) in enumerate(priority_targets, 1):
        print(f"\n{i}. {target}")
        print(f"   Findings: {stats['confirmed']}/{stats['findings']} confirmed"
              f" ({stats['accepted']} accepted by triage)")
        print(f"   Total payout: ${stats['total_payout']}")
        print(f"   Techniques: {', '.join(stats['techniques'][:5])}")
        if stats['techniques']:
            remaining = len(stats['techniques']) - 5
            if remaining > 0:
                print(f"   (+ {remaining} more)")

        if stats["severities"]:
            severity_str = ", ".join([f"{s}:{c}" for s, c in sorted(stats["severities"].items())])
            print(f"   Severities: {severity_str}")

    # Show recommendations if requested
    if args.recommendations:
        print("\n=== RECOMMENDATIONS ===")
        recommendations = get_recommendations(stack_stats, args.stack)

        for rec in recommendations:
            print(rec)

    print()


if __name__ == "__main__":
    main()
