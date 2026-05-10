"""
gcp_demo.py
End-to-end demonstration of the GCP IAM Policy Classification Engine.
Runs a labeled eval set of GCP policies and prints a full report.
"""

import json
import time
from pathlib import Path
from gcp_classifier import GCPClassifier
from gcp_adapter import GCPPolicyAdapter

# ── Eval set ──────────────────────────────────────────────────────────────────
# (filename, expected_verdict, description)
GCP_EVAL_SET = [
    ("gcp_policies/gcp_weak_1.json",   "WEAK",   "Owner role granted to allUsers"),
    ("gcp_policies/gcp_weak_2.json",   "WEAK",   "Editor role on allAuthenticatedUsers"),
    ("gcp_policies/gcp_weak_3.json",   "WEAK",   "Storage admin granted to allUsers"),
    ("gcp_policies/gcp_strong_1.json", "STRONG", "Storage objectViewer for specific user"),
    ("gcp_policies/gcp_strong_2.json", "STRONG", "Pub/Sub subscriber for specific service account"),
    ("gcp_policies/gcp_edge_1.json",   "WEAK",   "IAM serviceAccountUser on allAuthenticatedUsers with condition"),
]


def show_translation(policy_file: str) -> None:
    """Print the GCP → AWS translation for a given policy file."""
    adapter = GCPPolicyAdapter()
    gcp_policy = adapter.load(policy_file)
    aws_policy = adapter.translate(gcp_policy)
    # remove internal _source key for display
    display = {k: v for k, v in aws_policy.items() if not k.startswith("_")}
    print(json.dumps(display, indent=2))


def run_gcp_demo():
    classifier = GCPClassifier()

    print("=" * 70)
    print("GCP IAM POLICY CLASSIFICATION ENGINE — BONUS DEMO")
    print("=" * 70)

    # ── Show one translation example first ────────────────────────────────────
    print("\n── TRANSLATION EXAMPLE ──────────────────────────────────────────────")
    print("GCP INPUT (gcp_weak_1.json):")
    with open("gcp_policies/gcp_weak_1.json") as f:
        print(f.read())
    print("TRANSLATED TO AWS FORMAT:")
    show_translation("gcp_policies/gcp_weak_1.json")
    print()

    # ── Run eval set ──────────────────────────────────────────────────────────
    print("=" * 70)
    print(f"{'#':<4} {'Policy':<25} {'Expected':<10} {'Got':<10} {'Score':<8} {'Match':<6} {'Time'}")
    print("-" * 70)

    results = []
    correct = 0
    total_time = 0.0

    for i, (policy_file, expected, description) in enumerate(GCP_EVAL_SET, 1):
        start = time.time()
        report = classifier.classify(policy_file)
        elapsed = time.time() - start
        total_time += elapsed

        match = report.verdict == expected
        if match:
            correct += 1

        symbol = "✅" if match else "❌"
        fname  = Path(policy_file).name

        print(f"{i:<4} {fname:<25} {expected:<10} {report.verdict:<10} {report.score:<8} {symbol:<6} {elapsed:.1f}s")

        results.append({
            "policy":      policy_file,
            "description": description,
            "expected":    expected,
            "got":         report.verdict,
            "score":       report.score,
            "findings":    report.findings,
            "fixed_policy": report.fixed_policy,
            "match":       match,
            "time":        round(elapsed, 2),
        })

    # ── Summary ───────────────────────────────────────────────────────────────
    total = len(GCP_EVAL_SET)
    agreement_rate = correct / total * 100
    avg_time = total_time / total

    print("-" * 70)
    print(f"\nSUMMARY")
    print(f"  Total policies evaluated : {total}")
    print(f"  Correct classifications  : {correct}/{total}")
    print(f"  Agreement rate           : {agreement_rate:.1f}%")
    print(f"  Average time per policy  : {avg_time:.1f}s")
    print(f"  Total time               : {total_time:.1f}s")

    if agreement_rate >= 80:
        print(f"\n  ✅ GCP EVALUATION PASSED — agreement rate {agreement_rate:.1f}% >= 80%")
    else:
        print(f"\n  ❌ GCP EVALUATION FAILED — agreement rate {agreement_rate:.1f}% < 80%")

    # ── Detailed findings ─────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("DETAILED FINDINGS PER POLICY")
    print("=" * 70)

    for r in results:
        print(f"\n📋 {r['policy']} — {r['description']}")
        print(f"   Verdict : {r['got']} (expected: {r['expected']}) | Score: {r['score']}/10")
        print(f"   Findings:")
        for finding in r["findings"]:
            print(f"     • {finding}")
        if r["fixed_policy"]:
            print(f"   Fixed policy generated: ✅")

    # ── Save results ──────────────────────────────────────────────────────────
    output_path = "gcp_eval_results.json"
    with open(output_path, "w") as f:
        json.dump({
            "summary": {
                "total":              total,
                "correct":            correct,
                "agreement_rate":     f"{agreement_rate:.1f}%",
                "avg_time_seconds":   round(avg_time, 2),
                "total_time_seconds": round(total_time, 2),
            },
            "results": results,
        }, f, indent=2)

    print(f"\n  Detailed results saved to: {output_path}")
    print("=" * 70)


if __name__ == "__main__":
    run_gcp_demo()
