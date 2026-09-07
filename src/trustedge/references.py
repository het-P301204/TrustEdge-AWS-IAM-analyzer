"""Canonical documentation URLs cited by TrustEdge findings.

Every rubric decision in :mod:`trustedge.providers` links back to one of these.
If a rule cannot be traced to a primary source it does not belong in the
analyser - see ``docs/methodology.md``.

All URLs below were fetched and read while building this analyser. The date of
that verification is recorded in ``docs/research.md``.
"""

CONDITION_OPERATORS = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
    "reference_policies_elements_condition_operators.html"
)
IAM_STS_CONDITION_KEYS = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
    "reference_policies_iam-condition-keys.html"
)
GLOBAL_CONDITION_KEYS = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
    "reference_policies_condition-keys.html"
)
CONFUSED_DEPUTY = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html"
)
THIRD_PARTY_ACCESS = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
    "id_roles_common-scenarios_third-party.html"
)
OIDC_ROLE_SETUP = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
    "id_roles_create_for-idp_oidc.html"
)
OIDC_IDP_CONTROLS = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
    "id_roles_providers_oidc_secure-by-default.html"
)
ROLES_ANYWHERE_TRUST_MODEL = (
    "https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html"
)
CROSS_ACCOUNT_EVALUATION = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
    "reference_policies_evaluation-logic-cross-account.html"
)
CROSS_ACCOUNT_RESOURCE_ACCESS = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
    "access_policies-cross-account-resource-access.html"
)
PASS_ROLE = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html"
)
ACCESS_ANALYZER = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html"
)
IRSA = (
    "https://docs.aws.amazon.com/eks/latest/userguide/"
    "iam-roles-for-service-accounts.html"
)
