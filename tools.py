import json
import re
from criteria import (
    SCORES, ALL_SENSITIVE_ACTIONS,
    SENSITIVE_ACTIONS, VALID_VERSION, WEAK_THRESHOLD
)

MAX_POLICY_SIZE = 10240  # AWS max policy size excluding whitespace


class PolicyValidator:

    def validate(self, policy: dict, raw_string: str = None) -> dict:
        """
        Validates the structure and syntax of an IAM policy.
        Returns:
        {
            "valid": True/False,
            "errors": [...]
        }
        """
        errors = []

        # check 1 — single quotes (only if raw string provided)
        if raw_string is not None:
            if "'" in raw_string:
                errors.append(
                    "Invalid syntax: use double quotes \" not single quotes '"
                )

        # check 2 — max policy size (10,240 chars excluding whitespace)
        policy_str = json.dumps(policy)
        no_whitespace = policy_str.replace(" ", "").replace("\n", "").replace("\t", "")
        if len(no_whitespace) > MAX_POLICY_SIZE:
            errors.append(
                f"Policy exceeds maximum size of {MAX_POLICY_SIZE} characters "
                f"(current size: {len(no_whitespace)} chars, excluding whitespace)"
            )

        # check 3 — does Version field exist?
        if "Version" not in policy:
            errors.append("Missing Version field")

        # check 4 — optional Id field — if present must be a string
        if "Id" in policy and not isinstance(policy["Id"], str):
            errors.append("Id field must be a string")

        # check 5 — does Statement field exist?
        if "Statement" not in policy:
            errors.append("Missing Statement field")
            return {"valid": False, "errors": errors}

        # check 6 — is Statement a non-empty list?
        if not isinstance(policy["Statement"], list):
            errors.append("Statement must be a list")
            return {"valid": False, "errors": errors}

        if len(policy["Statement"]) == 0:
            errors.append("Statement list is empty")
            return {"valid": False, "errors": errors}

        # check 7 — validate each statement
        for i, statement in enumerate(policy["Statement"]):

            # Sid is optional but if present must contain only a-z A-Z 0-9
            if "Sid" in statement:
                if not re.match(r'^[a-zA-Z0-9]+$', statement["Sid"]):
                    errors.append(
                        f"Statement {i} Sid '{statement['Sid']}' contains invalid "
                        f"characters — only a-z, A-Z, 0-9 are allowed"
                    )

            # required fields — blocks can appear in any order
            for required_field in ["Effect", "Action", "Resource"]:
                if required_field not in statement:
                    if required_field == "Action" and "NotAction" in statement:
                        continue
                    if required_field == "Resource" and "NotResource" in statement:
                        continue
                    errors.append(
                        f"Statement {i} is missing required field: {required_field}"
                    )

            # Effect must be Allow or Deny
            if "Effect" in statement:
                if statement["Effect"] not in ["Allow", "Deny"]:
                    errors.append(
                        f"Statement {i} has invalid Effect: '{statement['Effect']}' "
                        f"— must be 'Allow' or 'Deny'"
                    )

        return {
            "valid": len(errors) == 0,
            "errors": errors
        }


class PolicyAnalyzer:

    def analyze(self, policy: dict) -> dict:
        """
        Runs all security checks on a validated policy.
        Returns:
        {
            "score": int,
            "findings": [...],
            "instant_weak": True/False
        }
        """
        score = 0
        findings = []
        instant_weak = False

        for result in [
            self.check_wildcards(policy),
            self.check_conditions(policy),
            self.check_action_scope(policy),
            self.check_resource_scope(policy),
            self.check_deny_statements(policy),
            self.check_principal(policy),
            self.check_version(policy),
        ]:
            score += result["score"]
            findings.extend(result["findings"])
            if result.get("instant_weak"):
                instant_weak = True

        return {
            "score": score,
            "findings": findings,
            "instant_weak": instant_weak
        }

    def check_wildcards(self, policy: dict) -> dict:
        """Category 1 and 2 — checks for Action: * and Resource: *"""
        score = 0
        findings = []
        instant_weak = False
        has_action_wildcard = False
        has_resource_wildcard = False

        for statement in policy["Statement"]:
            effect = statement.get("Effect", "")
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resources = statement.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            if effect == "Allow":
                if "*" in actions:
                    has_action_wildcard = True
                    score += SCORES["action_wildcard"]
                    findings.append(
                        "Action wildcard '*' found — grants all actions on all services"
                    )
                if "*" in resources:
                    has_resource_wildcard = True
                    score += SCORES["resource_wildcard"]
                    findings.append(
                        "Resource wildcard '*' found — applies to all AWS resources"
                    )

        if has_action_wildcard and has_resource_wildcard:
            instant_weak = True
            findings.append(
                "CRITICAL: Action '*' with Resource '*' — full unrestricted access"
            )

        return {"score": score, "findings": findings, "instant_weak": instant_weak}

    def check_conditions(self, policy: dict) -> dict:
        """Category 3 — checks for missing Condition blocks on Allow statements"""
        score = 0
        findings = []

        for statement in policy["Statement"]:
            if statement.get("Effect") == "Allow":
                if "Condition" not in statement:
                    score += SCORES["no_conditions"]
                    findings.append(
                        "Allow statement has no Condition block — "
                        "consider adding MFA or IP restrictions"
                    )
                    break

        return {"score": score, "findings": findings}

    def check_action_scope(self, policy: dict) -> dict:
        """Category 1 and 5 — checks for service wildcards and sensitive actions"""
        score = 0
        findings = []

        for statement in policy["Statement"]:
            effect = statement.get("Effect", "")
            has_condition = "Condition" in statement
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            if effect == "Allow":
                for action in actions:
                    if action != "*" and action.endswith(":*"):
                        score += SCORES["service_wildcard"]
                        findings.append(
                            f"Service wildcard '{action}' — "
                            f"grants all actions for this service"
                        )
                    if action in ALL_SENSITIVE_ACTIONS and not has_condition:
                        score += SCORES["sensitive_action"]
                        for category, actions_list in SENSITIVE_ACTIONS.items():
                            if action in actions_list:
                                findings.append(
                                    f"Sensitive action '{action}' without conditions "
                                    f"({category.replace('_', ' ')})"
                                )
                                break

        return {"score": score, "findings": findings}

    def check_resource_scope(self, policy: dict) -> dict:
        """Category 2 and 9 — checks for overly broad resource patterns"""
        score = 0
        findings = []

        for statement in policy["Statement"]:
            if statement.get("Effect") != "Allow":
                continue
            resources = statement.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            for resource in resources:
                if resource == "*":
                    continue
                if resource == "arn:aws:iam::*:*":
                    score += SCORES["broad_iam_resource"]
                    findings.append(
                        f"Broad IAM resource '{resource}' — "
                        f"applies to all IAM resources in account"
                    )
                elif resource == "arn:aws:s3:::*":
                    score += SCORES["broad_s3_resource"]
                    findings.append(
                        f"Broad S3 resource '{resource}' — applies to all buckets"
                    )
                elif resource.endswith("/*") or resource.endswith(":*"):
                    score += SCORES["broad_resource_pattern"]
                    findings.append(
                        f"Broad resource pattern '{resource}' — "
                        f"consider restricting to specific resources"
                    )

        return {"score": score, "findings": findings}

    def check_deny_statements(self, policy: dict) -> dict:
        """Category 4 and 7 — checks for missing Deny and inverted logic"""
        score = 0
        findings = []

        has_deny = any(
            s.get("Effect") == "Deny"
            for s in policy["Statement"]
        )

        if not has_deny:
            score += SCORES["no_deny"]
            findings.append(
                "No explicit Deny statements — "
                "consider adding Deny rules for sensitive operations"
            )

        for statement in policy["Statement"]:
            if statement.get("Effect") == "Allow":
                if "NotAction" in statement:
                    score += SCORES["not_action"]
                    findings.append(
                        "NotAction with Allow — effectively grants all actions "
                        "except the listed ones, which is overly permissive"
                    )
                if "NotResource" in statement:
                    score += SCORES["not_resource"]
                    findings.append(
                        "NotResource with Allow — effectively grants access to all "
                        "resources except the listed ones"
                    )

        return {"score": score, "findings": findings}

    def check_principal(self, policy: dict) -> dict:
        """Category 6 — checks for wildcard principals"""
        score = 0
        findings = []

        for statement in policy["Statement"]:
            principal = statement.get("Principal")
            if principal is None:
                continue
            if principal == "*":
                score += SCORES["principal_wildcard"]
                findings.append(
                    "Principal '*' — allows any entity including anonymous "
                    "internet users to assume this role"
                )
            elif isinstance(principal, dict):
                aws = principal.get("AWS", "")
                if aws == "*" or (isinstance(aws, list) and "*" in aws):
                    score += SCORES["principal_wildcard"]
                    findings.append(
                        "Principal AWS '*' — allows any AWS account to assume this role"
                    )

        return {"score": score, "findings": findings}

    def check_version(self, policy: dict) -> dict:
        """Category 8 — checks policy version"""
        score = 0
        findings = []

        if "Version" not in policy:
            score += SCORES["missing_version"]
            findings.append("Missing Version field")
        elif policy["Version"] != VALID_VERSION:
            score += SCORES["wrong_version"]
            findings.append(
                f"Policy version '{policy['Version']}' is outdated — "
                f"use '{VALID_VERSION}' for full feature support"
            )

        return {"score": score, "findings": findings}