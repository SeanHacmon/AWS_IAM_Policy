"""
eval.py
Evaluation script — runs the IAM classifier on a diverse set of policies
and produces a results report.
"""

import json
import time
import os
from pathlib import Path
from agent import IAMClassifier, Report

# ── Evaluation set ─────────────────────────────────────────────────────────────
# Each entry: (filename, expected_verdict)
EVAL_SET = [
    ("policies/weak_1.json",   "WEAK",   "Full wildcard — Action:* Resource:*"),
    ("policies/weak_2.json",   "WEAK",   "Service wildcard s3:* with no conditions"),
    ("policies/weak_3.json",   "WEAK",   "Sensitive IAM actions without conditions"),
    ("policies/weak_4.json",   "WEAK",   "Wildcard principal on AssumeRole"),
    ("policies/strong_1.json", "STRONG", "Read-only S3 with MFA and explicit Deny"),
    ("policies/strong_2.json", "STRONG", "Specific EC2 actions with IP condition"),
    ("policies/strong_3.json", "STRONG", "Least privilege Lambda execution role"),
    ("policies/edge_1.json",   "WEAK",   "Service wildcard with conditions (borderline)"),
    ("policies/score_3.json", "STRONG", "Specific S3 actions no conditions — score 3"),
]


def run_evaluation():
    classifier = IAMClassifier()
    results = []

    # create output folder for fixed policies
    output_dir = Path("output_policies")
    output_dir.mkdir(exist_ok=True)

    print("=" * 70)
    print("IAM POLICY CLASSIFICATION ENGINE — EVALUATION REPORT")
    print("=" * 70)
    print(f"{'#':<4} {'Policy':<20} {'Expected':<10} {'Got':<10} {'Score':<8} {'Match':<6} {'Time'}")
    print("-" * 70)

    total = len(EVAL_SET)
    correct = 0
    total_time = 0

    for i, (policy_file, expected, description) in enumerate(EVAL_SET, 1):
        start = time.time()
        report = classifier.classify(policy_file)
        elapsed = time.time() - start
        total_time += elapsed

        match = report.verdict == expected
        if match:
            correct += 1

        match_symbol = "✅" if match else "❌"

        print(
            f"{i:<4} {policy_file.split('/')[1]:<20} "
            f"{expected:<10} {report.verdict:<10} "
            f"{report.score:<8} {match_symbol:<6} {elapsed:.1f}s"
        )

        # save fixed policy as individual file if weak
        fixed_policy_path = None
        if report.fixed_policy:
            base_name = Path(policy_file).stem  # e.g. "weak_1"
            fixed_filename = output_dir / f"{base_name}_fixed.json"
            with open(fixed_filename, "w") as f:
                json.dump(report.fixed_policy, f, indent=2)
            fixed_policy_path = str(fixed_filename)
            print(f"     → Fixed policy saved to: {fixed_policy_path}")

        results.append({
            "policy": policy_file,
            "description": description,
            "expected": expected,
            "got": report.verdict,
            "score": report.score,
            "findings": report.findings,
            "fixed_policy": report.fixed_policy,
            "fixed_policy_path": fixed_policy_path,
            "match": match,
            "time": round(elapsed, 2),
        })

    # ── Summary ────────────────────────────────────────────────────────────────
    print("-" * 70)
    agreement_rate = correct / total * 100
    avg_time = total_time / total

    print(f"\nSUMMARY")
    print(f"  Total policies evaluated : {total}")
    print(f"  Correct classifications  : {correct}/{total}")
    print(f"  Agreement rate           : {agreement_rate:.1f}%")
    print(f"  Average time per policy  : {avg_time:.1f}s")
    print(f"  Total time               : {total_time:.1f}s")

    if agreement_rate >= 80:
        print(f"\n  ✅ EVALUATION PASSED — agreement rate {agreement_rate:.1f}% >= 80%")
    else:
        print(f"\n  ❌ EVALUATION FAILED — agreement rate {agreement_rate:.1f}% < 80%")

    # ── Save detailed results ──────────────────────────────────────────────────
    output_path = "eval_results.json"
    with open(output_path, "w") as f:
        json.dump({
            "summary": {
                "total": total,
                "correct": correct,
                "agreement_rate": f"{agreement_rate:.1f}%",
                "avg_time_seconds": round(avg_time, 2),
                "total_time_seconds": round(total_time, 2),
            },
            "results": results
        }, f, indent=2)

    print(f"\n  Detailed results saved to: {output_path}")
    print(f"  Fixed policies saved to  : output_policies/")
    print("=" * 70)

    # ── Print findings for each policy ────────────────────────────────────────
    print("\nDETAILED FINDINGS PER POLICY")
    print("=" * 70)
    for r in results:
        print(f"\n📋 {r['policy']} — {r['description']}")
        print(f"   Verdict: {r['got']} (expected: {r['expected']}) | Score: {r['score']}/10")
        print(f"   Findings:")
        for finding in r['findings']:
            print(f"     • {finding}")
        if r['fixed_policy']:
            print(f"   Fixed policy generated: ✅")


if __name__ == "__main__":
    run_evaluation()