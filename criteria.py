"""
IAM Policy Classification Criteria

A policy is classified as STRONG or WEAK based on the following rules:

The Policy will by classified via rating
By setting up a threshold:
ratings >= 5 -> WEAK
ratings < 5 -> STRONG

Category 1 - Actions
    * -> +5 rating
    <service>:* -> +3 rating

Category 2 - Resources
    * -> +5 rating

Category 3 - Conditions
    No conditions -> +2 rating

Category 4 - Effect
    No explicit deny Statements -> +1 rating

Category 5 - Sensitive Actions
    Any of the following without conditions -> +2 rating each

    Privilege escalation:
        iam:CreateUser
        iam:AttachUserPolicy
        iam:PutUserPolicy
        iam:AddUserToGroup
        iam:CreateLoginProfile
        iam:UpdateLoginProfile

    Credential theft:
        iam:CreateAccessKey
        iam:CreateServiceSpecificCredential

    Policy destruction:
        iam:DeletePolicy
        iam:DetachUserPolicy

    Role hijacking:
        sts:AssumeRole

    Data destruction:
        s3:DeleteObject
        s3:DeleteBucket

    Bucket takeover:
        s3:PutBucketPolicy
        s3:PutBucketAcl

    Network exposure:
        ec2:AuthorizeSecurityGroupIngress
        ec2:AuthorizeSecurityGroupEgress


Category 6 - Principal
    Principal: "*" -> +4 rating  (allows ANY entity to assume this role)
    Principal: {"AWS": "*"} -> +4 rating  (same, explicit form)

Category 7 - Inverted Logic
    NotAction used with Allow -> +3 rating
    NotResource used with Allow -> +3 rating

Category 8 - Policy Version
    Missing Version field -> +1 rating
    Version != "2012-10-17" -> +1 rating

Category 9 - Resource Scope
    Resource: "arn:aws:s3:::*" -> +2 rating  (all buckets)
    Resource: "arn:aws:iam::*:*" -> +3 rating  (all IAM resources)
    Resource ending in /* or :* -> +1 rating  (broad pattern)

INSTANT WEAK:
    Action: "*" AND Resource: "*" -> always WEAK regardless of score
"""

# ── Threshold ─────────────────────────────────────────────────────────────────
WEAK_THRESHOLD = 5

# ── Scoring weights ───────────────────────────────────────────────────────────
SCORES = {
    "action_wildcard":        5,
    "service_wildcard":       3,
    "resource_wildcard":      5,
    "broad_iam_resource":     3,
    "broad_s3_resource":      2,
    "broad_resource_pattern": 1,
    "no_conditions":          2,
    "no_deny":                1,
    "sensitive_action":       2,
    "principal_wildcard":     4,
    "not_action":             3,
    "not_resource":           3,
    "missing_version":        1,
    "wrong_version":          1,
}

SENSITIVE_ACTIONS = {
    "privilege_escalation": [
        "iam:CreateUser", "iam:AttachUserPolicy", "iam:PutUserPolicy",
        "iam:AddUserToGroup", "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
    ],
    "credential_theft": [
        "iam:CreateAccessKey", "iam:CreateServiceSpecificCredential",
    ],
    "policy_destruction": [
        "iam:DeletePolicy", "iam:DetachUserPolicy",
    ],
    "role_hijacking": [
        "sts:AssumeRole",
    ],
    "data_destruction": [
        "s3:DeleteObject", "s3:DeleteBucket",
    ],
    "bucket_takeover": [
        "s3:PutBucketPolicy", "s3:PutBucketAcl",
    ],
    "network_exposure": [
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:AuthorizeSecurityGroupEgress",
    ],
}

ALL_SENSITIVE_ACTIONS = [
    action
    for category in SENSITIVE_ACTIONS.values()
    for action in category
]

VALID_VERSION = "2012-10-17"