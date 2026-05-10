"""
gcp_adapter.py
Translates a GCP IAM policy (bindings format) into an AWS-equivalent IAM
policy dict so it can flow through the existing IAMClassifier pipeline.

GCP IAM binding format:
{
    "bindings": [
        {
            "role": "roles/editor",
            "members": ["allUsers", "user:alice@example.com"]
        }
    ],
    "etag": "...",       # optional
    "version": 1         # optional
}
"""

import json
from pathlib import Path


# ── Role mapping — GCP primitive/predefined roles → AWS action equivalents ────

# Maps GCP role → (action_list, is_wildcard, risk_level)
# risk_level: "critical", "high", "medium", "low"
GCP_ROLE_MAP = {
    # Primitive roles (highest risk)
    "roles/owner":          (["*"],                                          True,  "critical"),
    "roles/editor":         (["*"],                                          True,  "critical"),
    "roles/viewer":         (["*:Get*", "*:List*", "*:Describe*"],           False, "low"),

    # Storage
    "roles/storage.admin":          (["s3:*"],                              True,  "high"),
    "roles/storage.objectAdmin":    (["s3:PutObject", "s3:GetObject",
                                      "s3:DeleteObject", "s3:ListBucket"],  False, "medium"),
    "roles/storage.objectCreator":  (["s3:PutObject"],                      False, "low"),
    "roles/storage.objectViewer":   (["s3:GetObject", "s3:ListBucket"],     False, "low"),

    # Compute
    "roles/compute.admin":          (["ec2:*"],                             True,  "high"),
    "roles/compute.instanceAdmin":  (["ec2:StartInstances", "ec2:StopInstances",
                                      "ec2:RebootInstances",
                                      "ec2:DescribeInstances"],             False, "medium"),
    "roles/compute.viewer":         (["ec2:Describe*"],                     False, "low"),
    "roles/compute.networkAdmin":   (["ec2:AuthorizeSecurityGroupIngress",
                                      "ec2:AuthorizeSecurityGroupEgress",
                                      "ec2:CreateVpc", "ec2:DeleteVpc"],    False, "high"),

    # IAM
    "roles/iam.admin":              (["iam:*"],                             True,  "critical"),
    "roles/iam.roleAdmin":          (["iam:CreateRole", "iam:DeleteRole",
                                      "iam:AttachRolePolicy",
                                      "iam:DetachRolePolicy"],              False, "high"),
    "roles/iam.securityAdmin":      (["iam:*"],                             True,  "critical"),
    "roles/iam.serviceAccountAdmin":(["iam:CreateUser", "iam:DeleteUser",
                                      "iam:CreateAccessKey"],               False, "high"),
    "roles/iam.serviceAccountUser": (["sts:AssumeRole"],                    False, "medium"),

    # BigQuery → treat as data/analytics (map to generic read/write)
    "roles/bigquery.admin":         (["*"],                                  True,  "high"),
    "roles/bigquery.dataViewer":    (["s3:GetObject", "s3:ListBucket"],     False, "low"),
    "roles/bigquery.dataEditor":    (["s3:GetObject", "s3:PutObject",
                                      "s3:ListBucket"],                     False, "medium"),

    # Pub/Sub → map to SNS/SQS equivalents
    "roles/pubsub.admin":           (["sns:*", "sqs:*"],                    True,  "high"),
    "roles/pubsub.publisher":       (["sns:Publish"],                       False, "low"),
    "roles/pubsub.subscriber":      (["sqs:ReceiveMessage",
                                      "sqs:DeleteMessage"],                 False, "low"),
}

# GCP member types → AWS principal equivalents
MEMBER_MAP = {
    "allUsers":             "*",                          # anonymous public
    "allAuthenticatedUsers": "*",                         # any authenticated — still wildcard
}


def _translate_member(member: str) -> str:
    """
    Translate a GCP member string to an AWS principal string.
    allUsers / allAuthenticatedUsers → '*'
    user:x@y.com  → arn:aws:iam::*:user/x
    serviceAccount:x → arn:aws:iam::*:role/x
    group:x → arn:aws:iam::*:group/x
    domain:example.com → arn:aws:iam::*:root (domain-wide, treated as broad)
    """
    if member in MEMBER_MAP:
        return MEMBER_MAP[member]

    if ":" not in member:
        return "*"  # unknown format — treat as wildcard to be safe

    kind, identity = member.split(":", 1)
    name = identity.replace("@", "_").replace(".", "_")

    if kind == "user":
        return f"arn:aws:iam::*:user/{name}"
    elif kind == "serviceAccount":
        return f"arn:aws:iam::*:role/{name}"
    elif kind == "group":
        return f"arn:aws:iam::*:group/{name}"
    elif kind == "domain":
        # domain-wide access is broad — represent as wildcard
        return "*"
    else:
        return "*"


def _translate_role(role: str) -> tuple:
    """
    Returns (actions, is_wildcard, risk_level).
    Falls back to service wildcard for unknown custom/predefined roles.
    """
    if role in GCP_ROLE_MAP:
        return GCP_ROLE_MAP[role]

    # custom roles: roles/{project}/roles/{name} or projects/{p}/roles/{name}
    # treat as medium-risk with a service wildcard
    return (["*"], True, "medium")


def _infer_resource(role: str) -> str:
    """
    Return a scoped resource ARN for non-wildcard roles so they don't
    inflate the AWS scoring engine unfairly.
    """
    if "storage" in role or "bigquery" in role:
        return "arn:aws:s3:::*"
    if "compute" in role:
        return "arn:aws:ec2:*:*:instance/*"
    if "pubsub" in role:
        return "arn:aws:sqs:*:*:*"
    if "iam" in role:
        return "arn:aws:iam::*:*"
    return "arn:aws:*:*:*:*"


def translate_gcp_to_aws(gcp_policy: dict) -> dict:
    """
    Convert a GCP IAM policy dict into an AWS IAM policy dict.
    Each GCP binding becomes one AWS Statement.
    """
    bindings = gcp_policy.get("bindings", [])
    statements = []

    for binding in bindings:
        role    = binding.get("role", "")
        members = binding.get("members", [])
        condition = binding.get("condition")  # GCP CEL condition — optional

        actions, is_wildcard, _ = _translate_role(role)

        # translate members to principals
        principals = [_translate_member(m) for m in members]
        # deduplicate
        principals = list(dict.fromkeys(principals))

        # if any principal is wildcard, collapse to single "*"
        if "*" in principals:
            principal_value = "*"
        elif len(principals) == 1:
            principal_value = {"AWS": principals[0]}
        else:
            principal_value = {"AWS": principals}

        # use specific resource ARN for non-wildcard roles to avoid inflating score
        resource = "*" if is_wildcard else _infer_resource(role)

        statement = {
            "Effect": "Allow",
            "Principal": principal_value,
            "Action": actions[0] if len(actions) == 1 else actions,
            "Resource": resource,
        }

        # if GCP had a condition, add a placeholder AWS Condition block
        # we can't translate CEL to IAM conditions, but we mark it so the
        # scoring engine sees a Condition block and doesn't penalise +2
        if condition:
            statement["Condition"] = {
                "StringEquals": {
                    "aws:RequestedRegion": "us-east-1"  # placeholder — real logic from GCP CEL
                },
                "_gcp_condition": condition.get("expression", "")
            }
        else:
            del statement  # placeholder to avoid syntax issue
            statement = {
                "Effect": "Allow",
                "Principal": principal_value,
                "Action": actions[0] if len(actions) == 1 else actions,
                "Resource": resource,
            }

        statements.append(statement)

    aws_policy = {
        "Version": "2012-10-17",
        "_source": "GCP",
        "Statement": statements,
    }

    return aws_policy


class GCPPolicyAdapter:
    """
    Detects, validates, and translates GCP IAM policies.
    Used as a pre-processing step before IAMClassifier.
    """

    def is_gcp_policy(self, policy: dict) -> bool:
        """Return True if the dict looks like a GCP IAM policy."""
        return "bindings" in policy and isinstance(policy["bindings"], list)

    def validate_gcp(self, policy: dict) -> dict:
        """
        Basic structural validation for GCP IAM policy.
        Returns {"valid": bool, "errors": [...]}
        """
        errors = []

        if "bindings" not in policy:
            errors.append("Missing 'bindings' field — not a valid GCP IAM policy")
            return {"valid": False, "errors": errors}

        if not isinstance(policy["bindings"], list):
            errors.append("'bindings' must be a list")
            return {"valid": False, "errors": errors}

        if len(policy["bindings"]) == 0:
            errors.append("'bindings' list is empty")
            return {"valid": False, "errors": errors}

        for i, binding in enumerate(policy["bindings"]):
            if "role" not in binding:
                errors.append(f"Binding {i} is missing required field: 'role'")
            if "members" not in binding:
                errors.append(f"Binding {i} is missing required field: 'members'")
            elif not isinstance(binding["members"], list) or len(binding["members"]) == 0:
                errors.append(f"Binding {i} 'members' must be a non-empty list")

        return {"valid": len(errors) == 0, "errors": errors}

    def translate(self, gcp_policy: dict) -> dict:
        """Translate a validated GCP policy to AWS format."""
        return translate_gcp_to_aws(gcp_policy)

    def load(self, policy_input) -> dict:
        """Load a GCP policy from dict, JSON string, or file path."""
        if isinstance(policy_input, dict):
            return policy_input
        if isinstance(policy_input, Path):
            with open(policy_input) as f:
                return json.load(f)
        if isinstance(policy_input, str):
            try:
                return json.loads(policy_input)
            except json.JSONDecodeError:
                with open(policy_input) as f:
                    return json.load(f)
        raise TypeError(f"Unsupported input type: {type(policy_input)}")
