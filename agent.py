import json
import os
from pathlib import Path
from groq import Groq
from tools import PolicyValidator, PolicyAnalyzer
from criteria import WEAK_THRESHOLD


class Report:
    def __init__(self, verdict: str, score: int, findings: list, fixed_policy: dict = None):
        self.verdict = verdict
        self.score = score
        self.findings = findings
        self.fixed_policy = fixed_policy

    def to_json(self) -> str:
        output = {
            "verdict": self.verdict,
            "score": self.score,
            "findings": self.findings,
        }
        if self.fixed_policy:
            output["fixed_policy"] = self.fixed_policy
        return json.dumps(output, indent=2)

    def save(self, filename: str) -> None:
        with open(filename, "w") as f:
            f.write(self.to_json())
        print(f"Report saved to {filename}")

    def print_summary(self):
        print("\n" + "=" * 60)
        print(f"VERDICT : {self.verdict}")
        print(f"SCORE   : {self.score}/10")
        print(f"FINDINGS:")
        for i, finding in enumerate(self.findings, 1):
            print(f"  {i}. {finding}")
        if self.fixed_policy:
            print(f"\nFIXED POLICY:")
            print(json.dumps(self.fixed_policy, indent=2))
        print("=" * 60)


class IAMClassifier:

    def __init__(self):
        self.client = Groq()
        self.validator = PolicyValidator()
        self.analyzer = PolicyAnalyzer()

    # ── Private helpers ───────────────────────────────────────────────────────

    def _load_policy(self, policy_input) -> dict:
        """Convert any input type to a dict."""
        # already a dict
        if isinstance(policy_input, dict):
            return policy_input

        # pathlib Path object
        if isinstance(policy_input, Path):
            with open(policy_input) as f:
                return json.load(f)

        # string — could be JSON string or file path
        if isinstance(policy_input, str):
            try:
                return json.loads(policy_input)
            except json.JSONDecodeError:
                try:
                    with open(policy_input) as f:
                        return json.load(f)
                except FileNotFoundError:
                    raise FileNotFoundError(f"Policy file not found: {policy_input}")

        raise TypeError(f"Unsupported input type: {type(policy_input)}")

    def _call_llm(self, prompt: str) -> str:
        """Send a prompt to Groq and return the response."""
        response = self.client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,  # low temperature for consistent, precise output
        )
        return response.choices[0].message.content

    # ── Public interface ──────────────────────────────────────────────────────

    def classify(self, policy_input) -> Report:
        """
        Main entry point.
        1. Load and validate the policy
        2. Run security analysis
        3. Ask LLM to reason and confirm verdict
        4. Remediate if weak
        5. Return Report
        """
        # step 1 — load
        try:
            policy = self._load_policy(policy_input)
        except (FileNotFoundError, TypeError) as e:
            return Report(
                verdict="ERROR",
                score=0,
                findings=[str(e)],
            )

        # step 2 — validate structure
        raw_string = policy_input if isinstance(policy_input, str) else None
        validation = self.validator.validate(policy, raw_string=raw_string)
        if not validation["valid"]:
            return Report(
                verdict="INVALID",
                score=0,
                findings=validation["errors"],
            )

        # step 3 — run security analysis tools
        analysis = self.analyzer.analyze(policy)
        score = analysis["score"]
        findings = analysis["findings"]
        instant_weak = analysis["instant_weak"]

        # step 4 — ask LLM to add findings only (score is authoritative)
        _, llm_findings = self._classify_with_llm(
            policy, score, findings, instant_weak
        )

        # merge tool findings with LLM findings
        all_findings = findings + llm_findings

        # enforce score-based verdict — LLM cannot override the score
        # step 5 — score is authoritative for verdict, LLM cannot override
        if score >= WEAK_THRESHOLD or instant_weak:
            verdict = "WEAK"
        else:
            verdict = "STRONG"

        # step 6 — remediate only if truly weak
        fixed_policy = None
        if verdict == "WEAK":
            fixed_policy = self.remediate(policy, all_findings)

        return Report(
            verdict=verdict,
            score=min(score, 10),
            findings=all_findings,
            fixed_policy=fixed_policy,
        )

    def _classify_with_llm(
        self, policy: dict, score: int, findings: list, instant_weak: bool
    ) -> tuple[str, list]:
        """
        Ask the LLM to reason about the policy and confirm/refine the verdict.
        Returns (verdict, additional_findings)
        """
        prompt = f"""You are a senior AWS cloud security engineer.
You have analyzed an IAM policy using automated security tools and received the following results.

POLICY:
{json.dumps(policy, indent=2)}

AUTOMATED FINDINGS (score: {score}/10, threshold for WEAK is 5):
{chr(10).join(f'- {f}' for f in findings)}

INSTANT WEAK FLAG: {instant_weak}

Your task:
1. Review the policy and the automated findings
2. Identify any additional security issues the tools may have missed
3. Confirm the verdict based strictly on the score

Rules:
- If score >= 5 or instant_weak is True, the verdict MUST be WEAK
- If score < 5, the verdict MUST be STRONG — you cannot override this
- Your job is only to add findings, not to change the verdict
- Be concise — list only genuinely important additional findings

Respond in this exact JSON format with no extra text:
{{
    "verdict": "WEAK" or "STRONG",
    "additional_findings": ["finding 1", "finding 2"]
}}"""

        response = self._call_llm(prompt)

        # parse LLM response
        try:
            # strip markdown code blocks if present
            clean = response.strip()
            if clean.startswith("```"):
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:]
            result = json.loads(clean.strip())
            verdict = result.get("verdict", "WEAK")
            additional = result.get("additional_findings", [])
            return verdict, additional
        except json.JSONDecodeError:
            # if LLM response can't be parsed, fall back to score-based verdict
            verdict = "WEAK" if (score >= WEAK_THRESHOLD or instant_weak) else "STRONG"
            return verdict, []

    def remediate(self, policy: dict, findings: list) -> dict:
        """
        Ask the LLM to generate a fixed version of a weak policy.
        Returns the fixed policy as a dict.
        """
        prompt = f"""You are a senior AWS cloud security engineer.
The following IAM policy has been classified as WEAK due to these security issues:

ORIGINAL POLICY:
{json.dumps(policy, indent=2)}

SECURITY ISSUES FOUND:
{chr(10).join(f'- {f}' for f in findings)}

Your task:
1. Fix every security issue listed above
2. Preserve the original intent of the policy as much as possible
3. Apply the principle of least privilege
4. Add conditions where appropriate (e.g. MFA requirements)
5. Replace wildcards with specific resources and actions where possible

Respond with ONLY a valid IAM policy JSON with no extra text or explanation.
The response must be valid JSON that can be parsed directly."""

        response = self._call_llm(prompt)

        # parse the fixed policy
        try:
            clean = response.strip()
            if clean.startswith("```"):
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:]
            return json.loads(clean.strip())
        except json.JSONDecodeError:
            # if parsing fails return original with a note
            return {
                "note": "Remediation failed to parse — see findings for manual fixes",
                "original": policy
            }


if __name__ == "__main__":
    classifier = IAMClassifier()

    # quick test with a weak policy
    test_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }

    print("Testing with a weak policy...")
    report = classifier.classify(test_policy)
    report.print_summary()