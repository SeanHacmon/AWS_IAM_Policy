"""
gcp_classifier.py
Extends IAMClassifier to handle GCP IAM policies.

Flow:
  GCP policy input
      → GCPPolicyAdapter.validate_gcp()
      → GCPPolicyAdapter.translate()   (GCP → AWS format)
      → IAMClassifier.classify()       (existing pipeline, unchanged)
      → Report (with GCP context added to findings)
"""

import json
from pathlib import Path
from agent import IAMClassifier, Report
from gcp_adapter import GCPPolicyAdapter


class GCPClassifier:

    def __init__(self):
        self.adapter   = GCPPolicyAdapter()
        self.classifier = IAMClassifier()

    def classify(self, policy_input) -> Report:
        """
        Main entry point for GCP policies.
        Accepts dict, JSON string, or file path.
        """
        # step 1 — load
        try:
            gcp_policy = self.adapter.load(policy_input)
        except (FileNotFoundError, TypeError) as e:
            return Report(verdict="ERROR", score=0, findings=[str(e)])

        # step 2 — confirm it looks like a GCP policy
        if not self.adapter.is_gcp_policy(gcp_policy):
            return Report(
                verdict="ERROR",
                score=0,
                findings=["Input does not appear to be a GCP IAM policy — missing 'bindings' field"],
            )

        # step 3 — validate GCP structure
        validation = self.adapter.validate_gcp(gcp_policy)
        if not validation["valid"]:
            return Report(
                verdict="INVALID",
                score=0,
                findings=validation["errors"],
            )

        # step 4 — translate to AWS format
        aws_policy = self.adapter.translate(gcp_policy)

        # step 5 — run through existing AWS classifier pipeline
        report = self.classifier.classify(aws_policy)

        # step 6 — prepend GCP context to findings so it's clear in the output
        gcp_header = self._build_gcp_summary(gcp_policy)
        report.findings = gcp_header + report.findings

        return report

    def _build_gcp_summary(self, gcp_policy: dict) -> list:
        """Build a short list of findings summarising the original GCP bindings."""
        summary = ["[GCP Policy] Translated from GCP IAM bindings format"]
        for binding in gcp_policy.get("bindings", []):
            role    = binding.get("role", "unknown")
            members = binding.get("members", [])
            condition = binding.get("condition")
            line = f"[GCP Binding] role='{role}' members={members}"
            if condition:
                line += f" condition='{condition.get('expression', '')}'"
            summary.append(line)
        return summary


# ── CLI / demo entry point ────────────────────────────────────────────────────

if __name__ == "__main__":
    classifier = GCPClassifier()

    print("Testing with a weak GCP policy (roles/owner on allUsers)...")
    weak = {
        "bindings": [
            {
                "role": "roles/owner",
                "members": ["allUsers"]
            }
        ]
    }
    report = classifier.classify(weak)
    report.print_summary()
