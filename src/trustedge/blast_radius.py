"""Blast radius: what an identity that gets through the door can then do.

This is an **approximation of IAM authorisation, not an implementation of it**,
and the report says so. What is implemented:

* Allow statements from inline policies and from attached managed policies
  whose documents are present in the export.
* Action matching with IAM glob semantics (``*`` and ``?``), case-insensitive.
* ``NotAction`` handled as "everything except the listed patterns".
* A narrow, safe subset of Deny: an unconditional ``Deny`` on ``Resource: "*"``
  suppresses a capability whose probe action it matches. Anything more requires
  resource-level reasoning that a static export cannot support.
* Resource breadth, used to distinguish ``iam:PassRole`` on ``*`` from
  ``iam:PassRole`` on one narrowly named role.

What is **not** implemented, and is stated in every report:

* Permissions boundaries, service control policies, resource control policies
  and session policies. All four can shrink effective permissions.
* Conditional Deny evaluation and resource-pattern intersection.
* Resource-based policies in other accounts, which can add permissions the
  role's own policies do not show.
* Group memberships (roles do not have them, but a converted export might).

The consequence, spelled out for the reader: a HIGH or ADMIN tier means the
role's own policies grant those capabilities, not that an attacker has been
proven able to use them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .models import BlastRadius, BlastRadiusTier, Capability, IamExport, Role
from .policy import action_matches, as_str_list, policy_statements


@dataclass(frozen=True)
class Probe:
    """One capability to look for, and why it matters."""

    code: str
    category: str  # "admin" | "escalation" | "data_plane"
    action: str
    detail: str
    #: "admin", "high", "moderate" or "low" - how much this alone contributes.
    weight: str


#: Escalation primitives. Each of these lets a principal acquire permissions it
#: was not granted, which is what makes a trust-boundary weakness compound.
ESCALATION_PROBES: Tuple[Probe, ...] = (
    Probe(
        "iam_pass_role",
        "escalation",
        "iam:PassRole",
        "Can pass an IAM role to an AWS service. AWS warns that you should "
        "\"make sure that a user doesn't pass a role where the role has more "
        "permissions than you want the user to have\" - combined with a "
        "compute-create permission this yields the passed role's privileges.",
        "moderate",
    ),
    Probe(
        "iam_create_policy_version",
        "escalation",
        "iam:CreatePolicyVersion",
        "Can create a new version of a managed policy. A new default version "
        "can grant arbitrary permissions to every principal the policy is "
        "attached to.",
        "high",
    ),
    Probe(
        "iam_set_default_policy_version",
        "escalation",
        "iam:SetDefaultPolicyVersion",
        "Can switch a managed policy to a different existing version, which "
        "may be more permissive than the current default.",
        "high",
    ),
    Probe(
        "iam_attach_role_policy",
        "escalation",
        "iam:AttachRolePolicy",
        "Can attach any managed policy - including AdministratorAccess - to a "
        "role.",
        "high",
    ),
    Probe(
        "iam_attach_user_policy",
        "escalation",
        "iam:AttachUserPolicy",
        "Can attach any managed policy to an IAM user.",
        "high",
    ),
    Probe(
        "iam_attach_group_policy",
        "escalation",
        "iam:AttachGroupPolicy",
        "Can attach any managed policy to an IAM group.",
        "high",
    ),
    Probe(
        "iam_put_role_policy",
        "escalation",
        "iam:PutRolePolicy",
        "Can write an inline policy onto a role, granting it arbitrary "
        "permissions.",
        "high",
    ),
    Probe(
        "iam_put_user_policy",
        "escalation",
        "iam:PutUserPolicy",
        "Can write an inline policy onto an IAM user.",
        "high",
    ),
    Probe(
        "iam_update_assume_role_policy",
        "escalation",
        "iam:UpdateAssumeRolePolicy",
        "Can rewrite any role's trust policy - the exact object this tool "
        "analyses. A principal with this permission can make itself trusted by "
        "any role in the account.",
        "high",
    ),
    Probe(
        "iam_create_access_key",
        "escalation",
        "iam:CreateAccessKey",
        "Can mint long-lived access keys for an IAM user, converting temporary "
        "access into persistent access.",
        "high",
    ),
    Probe(
        "iam_create_login_profile",
        "escalation",
        "iam:CreateLoginProfile",
        "Can set a console password for an IAM user that does not have one.",
        "high",
    ),
    Probe(
        "iam_update_login_profile",
        "escalation",
        "iam:UpdateLoginProfile",
        "Can change an IAM user's console password.",
        "high",
    ),
    Probe(
        "iam_add_user_to_group",
        "escalation",
        "iam:AddUserToGroup",
        "Can add a user to a group, inheriting that group's permissions.",
        "high",
    ),
    Probe(
        "iam_create_role",
        "escalation",
        "iam:CreateRole",
        "Can create new roles. Paired with iam:AttachRolePolicy or "
        "iam:PutRolePolicy this is a direct route to administrative access.",
        "moderate",
    ),
    Probe(
        "sts_assume_role",
        "escalation",
        "sts:AssumeRole",
        "Can assume other roles, so this role is a potential first hop in a "
        "role chain rather than an endpoint.",
        "moderate",
    ),
    Probe(
        "sts_get_federation_token",
        "escalation",
        "sts:GetFederationToken",
        "Can mint a federated-user session, which is a way to hand this role's "
        "permissions to another party.",
        "moderate",
    ),
    Probe(
        "kms_put_key_policy",
        "escalation",
        "kms:PutKeyPolicy",
        "Can rewrite a KMS key policy and grant itself decrypt access to data "
        "it should not be able to read.",
        "high",
    ),
    Probe(
        "s3_put_bucket_policy",
        "escalation",
        "s3:PutBucketPolicy",
        "Can rewrite a bucket policy, including making the bucket readable by "
        "an external principal.",
        "high",
    ),
    Probe(
        "lambda_create_function",
        "escalation",
        "lambda:CreateFunction",
        "Can create a Lambda function; with iam:PassRole this executes code "
        "under another role's identity.",
        "moderate",
    ),
    Probe(
        "lambda_update_function_code",
        "escalation",
        "lambda:UpdateFunctionCode",
        "Can replace the code of an existing function, executing arbitrary "
        "code under that function's execution role.",
        "high",
    ),
    Probe(
        "ec2_run_instances",
        "escalation",
        "ec2:RunInstances",
        "Can launch EC2 instances; with iam:PassRole this attaches an instance "
        "profile and yields that role's credentials via IMDS.",
        "moderate",
    ),
    Probe(
        "cloudformation_create_stack",
        "escalation",
        "cloudformation:CreateStack",
        "Can create a CloudFormation stack; with iam:PassRole the stack runs "
        "with the passed role's permissions.",
        "moderate",
    ),
    Probe(
        "ssm_send_command",
        "escalation",
        "ssm:SendCommand",
        "Can execute commands on managed instances, obtaining whatever "
        "credentials those instances hold.",
        "high",
    ),
    Probe(
        "ssm_start_session",
        "escalation",
        "ssm:StartSession",
        "Can open an interactive session on managed instances.",
        "high",
    ),
    Probe(
        "codebuild_create_project",
        "escalation",
        "codebuild:CreateProject",
        "Can create a build project; with iam:PassRole the build runs under "
        "the passed service role.",
        "moderate",
    ),
    Probe(
        "ecs_register_task_definition",
        "escalation",
        "ecs:RegisterTaskDefinition",
        "Can register a task definition; with iam:PassRole the task runs under "
        "the passed task role.",
        "moderate",
    ),
    Probe(
        "glue_create_dev_endpoint",
        "escalation",
        "glue:CreateDevEndpoint",
        "Can create a Glue development endpoint; with iam:PassRole this gives "
        "interactive access under the passed role.",
        "moderate",
    ),
    Probe(
        "sagemaker_create_notebook",
        "escalation",
        "sagemaker:CreateNotebookInstance",
        "Can create a SageMaker notebook; with iam:PassRole this gives "
        "interactive access under the passed role.",
        "moderate",
    ),
    Probe(
        "datapipeline_create_pipeline",
        "escalation",
        "datapipeline:CreatePipeline",
        "Can create a Data Pipeline; with iam:PassRole the pipeline runs under "
        "the passed role.",
        "moderate",
    ),
)

#: Data-plane reach. Not privilege escalation, but the reason an attacker wants
#: the credentials in the first place.
DATA_PROBES: Tuple[Probe, ...] = (
    Probe(
        "secrets_read",
        "data_plane",
        "secretsmanager:GetSecretValue",
        "Can read Secrets Manager secret values.",
        "high",
    ),
    Probe(
        "ssm_parameter_read",
        "data_plane",
        "ssm:GetParameter",
        "Can read SSM parameters, including SecureString parameters if KMS "
        "decrypt is also allowed.",
        "moderate",
    ),
    Probe(
        "kms_decrypt",
        "data_plane",
        "kms:Decrypt",
        "Can decrypt data encrypted under KMS keys.",
        "high",
    ),
    Probe(
        "s3_read",
        "data_plane",
        "s3:GetObject",
        "Can read S3 object contents.",
        "moderate",
    ),
    Probe(
        "s3_write",
        "data_plane",
        "s3:PutObject",
        "Can write S3 objects, which for a bucket that feeds a build or "
        "deployment pipeline is a supply-chain concern.",
        "moderate",
    ),
    Probe(
        "s3_delete",
        "data_plane",
        "s3:DeleteObject",
        "Can delete S3 objects.",
        "moderate",
    ),
    Probe(
        "dynamodb_read",
        "data_plane",
        "dynamodb:Scan",
        "Can read DynamoDB table contents in bulk.",
        "moderate",
    ),
    Probe(
        "dynamodb_write",
        "data_plane",
        "dynamodb:PutItem",
        "Can write DynamoDB items.",
        "moderate",
    ),
    Probe(
        "rds_data_execute",
        "data_plane",
        "rds-data:ExecuteStatement",
        "Can run SQL against Aurora Serverless via the Data API.",
        "high",
    ),
    Probe(
        "rds_snapshot_restore",
        "data_plane",
        "rds:RestoreDBInstanceFromDBSnapshot",
        "Can restore a database snapshot into a new instance, a common route to "
        "reading production data without touching the production database.",
        "high",
    ),
    Probe(
        "ec2_snapshot_share",
        "data_plane",
        "ec2:ModifySnapshotAttribute",
        "Can change snapshot permissions, including sharing an EBS snapshot "
        "with another AWS account.",
        "high",
    ),
    Probe(
        "logs_read",
        "data_plane",
        "logs:FilterLogEvents",
        "Can read CloudWatch Logs contents.",
        "low",
    ),
    Probe(
        "ecr_pull",
        "data_plane",
        "ecr:BatchGetImage",
        "Can pull container images from ECR.",
        "low",
    ),
    Probe(
        "ses_send",
        "data_plane",
        "ses:SendEmail",
        "Can send email as your verified domains, which enables convincing "
        "phishing from your own identity.",
        "moderate",
    ),
    Probe(
        "sqs_receive",
        "data_plane",
        "sqs:ReceiveMessage",
        "Can read queued messages.",
        "low",
    ),
)

ALL_PROBES: Tuple[Probe, ...] = ESCALATION_PROBES + DATA_PROBES

#: Actions that create or control compute. Combined with iam:PassRole these
#: turn "can pass a role" into "can run code as that role".
COMPUTE_CREATE_CODES = frozenset(
    {
        "lambda_create_function",
        "ec2_run_instances",
        "cloudformation_create_stack",
        "codebuild_create_project",
        "ecs_register_task_definition",
        "glue_create_dev_endpoint",
        "sagemaker_create_notebook",
        "datapipeline_create_pipeline",
        "ssm_send_command",
    }
)

#: Service-wide wildcards that make a data-plane grant materially worse.
BROAD_SERVICE_WILDCARDS = (
    "s3:*",
    "secretsmanager:*",
    "dynamodb:*",
    "kms:*",
    "rds:*",
    "ssm:*",
    "sqs:*",
    "sns:*",
    "ecr:*",
    "logs:*",
)


@dataclass
class _Statement:
    policy_name: str
    source: str
    actions: List[str]
    not_actions: List[str]
    resources: List[str]
    has_not_resource: bool
    conditioned: bool

    def covers(self, action: str) -> bool:
        if self.not_actions:
            return not any(action_matches(p, action) for p in self.not_actions)
        return any(action_matches(p, action) for p in self.actions)

    @property
    def broad_resource(self) -> bool:
        if self.has_not_resource:
            return True
        return any(r.strip() == "*" for r in self.resources)


def resolve(role: Role, export: Optional[IamExport] = None) -> BlastRadius:
    """Compute the blast radius of a role from its permission policies."""
    radius = BlastRadius()
    allows: List[_Statement] = []
    denies: List[_Statement] = []

    for ref in role.policies:
        if ref.document is None:
            radius.unresolved_policies.append(ref.name)
            continue
        statements, problems = policy_statements(ref.document)
        for problem in problems:
            radius.limitations.append(
                "Policy %s: %s (its permissions are not counted)."
                % (ref.name, problem)
            )
        for raw in statements:
            parsed = _parse_permission_statement(raw, ref.name, ref.source)
            if parsed is None:
                continue
            effect = raw.get("Effect")
            if isinstance(effect, str) and effect.lower() == "deny":
                denies.append(parsed)
                radius.deny_statements_seen += 1
            else:
                allows.append(parsed)
                radius.statements_evaluated += 1
                if parsed.has_not_resource:
                    radius.limitations.append(
                        "Policy %s uses NotResource. TrustEdge reads "
                        "\"everything except\" as Resource '*' rather than "
                        "computing the complement, so a capability from that "
                        "statement is treated as account-wide."
                        % parsed.policy_name
                    )

    radius.has_permissions_boundary = bool(role.permissions_boundary_arn)

    if not allows:
        radius.tier = BlastRadiusTier.UNKNOWN
        if radius.unresolved_policies:
            radius.reasoning.append(
                "No permission policy document was resolvable for this role "
                "(%d attached policy document(s) missing from the export), so "
                "blast radius is unknown rather than low."
                % len(radius.unresolved_policies)
            )
        else:
            radius.reasoning.append(
                "This role has no Allow statements in the export, so it grants "
                "no permissions that TrustEdge can see."
            )
            radius.tier = BlastRadiusTier.LOW
        _add_standard_limitations(radius, role)
        return radius

    admin = _detect_admin(allows, denies)
    if admin is not None:
        radius.capabilities.append(admin)

    for probe in ALL_PROBES:
        capability = _match_probe(probe, allows, denies)
        if capability is not None:
            radius.capabilities.append(capability)

    radius.capabilities.extend(_detect_service_wildcards(allows, denies))
    radius.capabilities.extend(_detect_combinations(radius.capabilities))

    radius.tier = _assign_tier(radius)
    _explain(radius, role)
    _add_standard_limitations(radius, role)
    return radius


# --------------------------------------------------------------------------
# Statement parsing
# --------------------------------------------------------------------------


def _parse_permission_statement(
    raw: Dict[str, object], policy_name: str, source: str
) -> Optional[_Statement]:
    actions = as_str_list(raw.get("Action"))
    not_actions = as_str_list(raw.get("NotAction"))
    if not actions and not not_actions:
        return None
    resources = as_str_list(raw.get("Resource"))
    not_resources = as_str_list(raw.get("NotResource"))
    has_not_resource = bool(not_resources)
    if has_not_resource:
        # "Everything except X" is broad. Recording it as ``["*"]`` keeps the
        # capability's resource_patterns consistent with broad_resource, which
        # the tiering reads - leaving it empty made a NotResource statement
        # grade a tier lower than the equivalent Resource: "*" one.
        resources = ["*"]
    elif not resources:
        # An identity policy statement requires Resource; treat a missing one as
        # broad so the finding errs towards visibility, and say so.
        resources = ["*"]
    return _Statement(
        policy_name=policy_name,
        source=source,
        actions=actions,
        not_actions=not_actions,
        resources=resources,
        has_not_resource=has_not_resource,
        conditioned=isinstance(raw.get("Condition"), dict)
        and bool(raw.get("Condition")),
    )


def _denied(action: str, denies: Sequence[_Statement]) -> bool:
    """Whether a probe action is suppressed by a Deny TrustEdge is sure about.

    Only unconditional denies on ``Resource: "*"`` count. A conditional deny, or
    one scoped to specific resources, may or may not apply to the action an
    attacker would choose, and guessing would trade false positives for false
    negatives - the worse trade for a security tool.
    """
    for statement in denies:
        if statement.conditioned:
            continue
        if not statement.broad_resource:
            continue
        if statement.covers(action):
            return True
    return False


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------


def _detect_admin(
    allows: Sequence[_Statement], denies: Sequence[_Statement]
) -> Optional[Capability]:
    for statement in allows:
        if not statement.broad_resource:
            continue
        # A NotAction-only statement is admin-equivalent only if the exclusion
        # list still leaves the IAM write path open; a NotAction of ["iam:*"]
        # is broad but is not administrator-equivalent.
        full_wildcard = any(a.strip() == "*" for a in statement.actions) or (
            bool(statement.not_actions)
            and not statement.actions
            and statement.covers("iam:PutRolePolicy")
        )
        if full_wildcard and not _denied("iam:PutRolePolicy", denies):
            return Capability(
                category="admin",
                code="admin_equivalent",
                detail=(
                    "Allows every action on every resource. Anyone who assumes "
                    "this role is an administrator of the account."
                    if any(a.strip() == "*" for a in statement.actions)
                    else "Allows every action except a NotAction list, on every "
                    "resource. Treat as administrator-equivalent unless the "
                    "NotAction list is verified to remove all IAM and "
                    "credential-granting actions."
                ),
                source_policy="%s (%s)" % (statement.policy_name, statement.source),
                action_pattern=(
                    statement.actions[0]
                    if statement.actions
                    else "NotAction:%s" % ",".join(statement.not_actions)
                ),
                resource_patterns=list(statement.resources),
                conditioned=statement.conditioned,
            )
        if any(action_matches(a, "iam:PutRolePolicy") for a in statement.actions) and any(
            action_matches(a, "iam:AttachRolePolicy") for a in statement.actions
        ):
            if not _denied("iam:PutRolePolicy", denies):
                return Capability(
                    category="admin",
                    code="admin_via_iam_control",
                    detail=(
                        "Allows both iam:PutRolePolicy and iam:AttachRolePolicy "
                        "on all resources, which is administrator-equivalent: "
                        "the role can grant itself any permission."
                    ),
                    source_policy="%s (%s)"
                    % (statement.policy_name, statement.source),
                    action_pattern=", ".join(statement.actions[:4]),
                    resource_patterns=list(statement.resources),
                    conditioned=statement.conditioned,
                )
    return None


def _match_probe(
    probe: Probe, allows: Sequence[_Statement], denies: Sequence[_Statement]
) -> Optional[Capability]:
    if _denied(probe.action, denies):
        return None
    for statement in allows:
        if not statement.covers(probe.action):
            continue
        matching_pattern = next(
            (p for p in statement.actions if action_matches(p, probe.action)),
            "NotAction:%s" % ",".join(statement.not_actions),
        )
        return Capability(
            category=probe.category,
            code=probe.code,
            detail=probe.detail,
            source_policy="%s (%s)" % (statement.policy_name, statement.source),
            action_pattern=matching_pattern,
            resource_patterns=list(statement.resources),
            conditioned=statement.conditioned,
        )
    return None


def _detect_service_wildcards(
    allows: Sequence[_Statement], denies: Sequence[_Statement]
) -> List[Capability]:
    out: List[Capability] = []
    seen: Set[str] = set()
    for statement in allows:
        for pattern in statement.actions:
            normalised = pattern.strip().lower()
            if normalised not in BROAD_SERVICE_WILDCARDS or normalised in seen:
                continue
            if _denied(pattern, denies):
                continue
            seen.add(normalised)
            out.append(
                Capability(
                    category="data_plane",
                    code="service_wildcard_%s" % normalised.split(":")[0],
                    detail=(
                        "Grants every action in the %s service%s. A "
                        "service-wide wildcard means the role's reach grows "
                        "automatically as AWS adds actions."
                        % (
                            normalised.split(":")[0],
                            " on all resources" if statement.broad_resource else "",
                        )
                    ),
                    source_policy="%s (%s)"
                    % (statement.policy_name, statement.source),
                    action_pattern=pattern,
                    resource_patterns=list(statement.resources),
                    conditioned=statement.conditioned,
                )
            )
    return out


def _detect_combinations(capabilities: Sequence[Capability]) -> List[Capability]:
    codes = {c.code for c in capabilities}
    out: List[Capability] = []
    if "iam_pass_role" in codes:
        compute = sorted(codes & COMPUTE_CREATE_CODES)
        if compute:
            pass_role = next(c for c in capabilities if c.code == "iam_pass_role")
            out.append(
                Capability(
                    category="escalation",
                    code="passrole_plus_compute",
                    detail=(
                        "Holds iam:PassRole together with %s. That combination "
                        "lets this role execute code as any role it is allowed "
                        "to pass, so its effective permissions are the union of "
                        "its own and every passable role's."
                        % ", ".join(compute)
                    ),
                    source_policy=pass_role.source_policy,
                    action_pattern="iam:PassRole + compute creation",
                    resource_patterns=list(pass_role.resource_patterns),
                    conditioned=pass_role.conditioned,
                )
            )
    if "iam_create_role" in codes and (
        {"iam_attach_role_policy", "iam_put_role_policy"} & codes
    ):
        out.append(
            Capability(
                category="escalation",
                code="create_role_plus_policy",
                detail=(
                    "Can create a role and attach or inline a policy to it, "
                    "which is a direct path to an administrator-equivalent "
                    "identity."
                ),
                source_policy="multiple",
                action_pattern="iam:CreateRole + iam:AttachRolePolicy/PutRolePolicy",
                resource_patterns=["*"],
            )
        )
    return out


# --------------------------------------------------------------------------
# Tiering
# --------------------------------------------------------------------------

_HIGH_WEIGHT_CODES = frozenset(
    probe.code for probe in ESCALATION_PROBES if probe.weight == "high"
) | {"passrole_plus_compute", "create_role_plus_policy"}

_HIGH_WEIGHT_DATA = frozenset(
    probe.code for probe in DATA_PROBES if probe.weight == "high"
)


def _assign_tier(radius: BlastRadius) -> str:
    if radius.admin_equivalent:
        return BlastRadiusTier.ADMIN

    codes = {c.code for c in radius.capabilities}
    broad = {
        c.code
        for c in radius.capabilities
        if any(r.strip() == "*" for r in c.resource_patterns)
    }

    high_escalation = codes & _HIGH_WEIGHT_CODES
    if high_escalation:
        # A high-weight primitive scoped to specific resources is a real but
        # smaller problem than the same primitive on "*".
        if high_escalation & broad:
            return BlastRadiusTier.HIGH
        return BlastRadiusTier.MODERATE

    if codes & _HIGH_WEIGHT_DATA and (codes & _HIGH_WEIGHT_DATA) & broad:
        return BlastRadiusTier.HIGH

    if any(c.code.startswith("service_wildcard_") for c in radius.capabilities):
        return BlastRadiusTier.HIGH if broad else BlastRadiusTier.MODERATE

    if codes:
        return BlastRadiusTier.MODERATE

    return BlastRadiusTier.LOW


def _explain(radius: BlastRadius, role: Role) -> None:
    if radius.admin_equivalent:
        radius.reasoning.append(
            "Administrator-equivalent: %s"
            % next(c.detail for c in radius.capabilities if c.category == "admin")
        )
    escalation = radius.escalation_primitives
    if escalation:
        radius.reasoning.append(
            "Escalation primitives held: %s."
            % ", ".join(sorted({c.code for c in escalation}))
        )
    data = radius.data_plane
    if data:
        radius.reasoning.append(
            "Data-plane reach: %s." % ", ".join(sorted({c.code for c in data}))
        )
    if not radius.capabilities:
        radius.reasoning.append(
            "%d Allow statement(s) evaluated and none matched a "
            "security-relevant capability, so this role is treated as low "
            "blast radius." % radius.statements_evaluated
        )
    narrow = [
        c.code
        for c in radius.capabilities
        if c.resource_patterns and not any(r.strip() == "*" for r in c.resource_patterns)
    ]
    if narrow:
        radius.reasoning.append(
            "Resource-scoped rather than account-wide: %s. TrustEdge downgrades "
            "these relative to the same permission on Resource '*'."
            % ", ".join(sorted(set(narrow)))
        )
    if radius.unresolved_policies:
        radius.reasoning.append(
            "This is a lower bound: %d attached managed policy document(s) were "
            "not in the export (%s)."
            % (
                len(radius.unresolved_policies),
                ", ".join(radius.unresolved_policies[:5]),
            )
        )


def _add_standard_limitations(radius: BlastRadius, role: Role) -> None:
    radius.limitations.append(
        "TrustEdge approximates IAM authorisation. It does not evaluate "
        "permissions boundaries, service control policies, resource control "
        "policies or session policies, all of which can reduce effective "
        "permissions."
    )
    if role.permissions_boundary_arn:
        radius.limitations.append(
            "This role has a permissions boundary (%s). Its effective "
            "permissions are the intersection of the boundary and the policies "
            "counted here, so the real blast radius may be smaller."
            % role.permissions_boundary_arn
        )
    if radius.deny_statements_seen:
        radius.limitations.append(
            "%d Deny statement(s) were found. Only unconditional denies on "
            "Resource '*' are applied; conditional or resource-scoped denies "
            "are listed but not evaluated." % radius.deny_statements_seen
        )
    radius.limitations.append(
        "Resource-based policies in other accounts can grant this role access "
        "that its own policies do not show."
    )
