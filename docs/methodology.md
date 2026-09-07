# TrustEdge methodology

Every number in a TrustEdge report can be reproduced by hand from this
document. If a grade in the output cannot be justified from the rules here,
that is a bug.

---

## 1. The shape of the model

```
exposure grade  ──┐
                  ├──►  risk = round(100 × exposure_weight × blast_weight)  ──► severity band
blast radius   ───┘
```

**Why a product and not a sum.** A sum lets one factor carry a finding to the
top on its own, so a locked-down administrator role and a wide-open role with
no permissions both land near the middle - which is exactly the triage error the
project exists to fix. A product has the property that driving *either* factor
towards zero drives the risk towards zero, which matches how a reviewer
actually prioritises: a door worth walking through, that is easy to walk
through.

The consequence is deliberate and visible in the fixtures: a STRONG door onto
an `AdministratorAccess` role scores 15 (MEDIUM), and an OPEN door onto a role
that can only call `sts:GetCallerIdentity` also scores 15 (MEDIUM). Neither is
an emergency. A WEAK door onto an admin role scores 75 (CRITICAL).

---

## 2. Exposure weights

Defined once, in `ExposureGrade.SCORES` (`models.py`), so the rubric and the
arithmetic cannot drift apart.

| Grade | Weight | Meaning |
|---|---:|---|
| `OPEN` | 1.00 | No effective restriction. Any identity that can reach the relevant STS API passes. |
| `WEAK` | 0.75 | A restriction exists but leaves a large, attacker-reachable set (a whole external account; a whole GitHub org; any certificate from any trust anchor). |
| `MODERATE` | 0.45 | Bounded to a real tenant, repository or account, but not to a specific workload. |
| `STRONG` | 0.15 | Pinned to a specific external identity with a non-guessable condition. |
| `INTERNAL` | 0.05 | The principal is inside this account, or is a compute-attachment service principal. Not an inbound trust boundary. |
| `NOT_DETERMINED` | 0.40 | There is a door and TrustEdge could not grade it. Severity capped at MEDIUM. |
| `NOT_APPLICABLE` | 0.00 | The statement grants no assume-role action, so it is not a door. |

`STRONG` is 0.15 rather than 0 on purpose: a strong condition is not a proof of
safety, and a strong door onto an admin role is still worth a look.

---

## 3. Blast-radius weights

| Tier | Weight | Assigned when |
|---|---:|---|
| `ADMIN` | 1.00 | Administrator-equivalent (see §5.1). |
| `HIGH` | 0.75 | A high-weight escalation primitive on `Resource: "*"`, a high-weight data capability on `Resource: "*"`, or a service-wide wildcard on `Resource: "*"`. |
| `MODERATE` | 0.45 | Any of the above but resource-scoped; or `iam:PassRole`/`sts:AssumeRole` alone; or any other detected capability. |
| `LOW` | 0.15 | Allow statements were evaluated and none matched a security-relevant capability. |
| `UNKNOWN` | 0.40 | No permission policy document was resolvable. Deliberately *not* LOW: absence of evidence is not evidence of absence. |

---

## 4. Severity bands

| Risk score | Severity |
|---:|---|
| ≥ 60 | `CRITICAL` |
| ≥ 35 | `HIGH` |
| ≥ 15 | `MEDIUM` |
| ≥ 5 | `LOW` |
| < 5 | `INFO` |

Two caps override the band, because TrustEdge will not raise an alarm on the
strength of a grade it could not determine:

* `NOT_DETERMINED` exposure ⇒ severity capped at `MEDIUM`.
* `INTERNAL` exposure ⇒ capped at `LOW`.
* `NOT_APPLICABLE` ⇒ capped at `INFO`.

The full matrix, which you can check against `ranking.risk_score`:

| | ADMIN | HIGH | MODERATE | LOW | UNKNOWN |
|---|---|---|---|---|---|
| **OPEN** | 100 CRITICAL | 75 CRITICAL | 45 HIGH | 15 MEDIUM | 40 HIGH |
| **WEAK** | 75 CRITICAL | 56 HIGH | 34 MEDIUM | 11 LOW | 30 MEDIUM |
| **MODERATE** | 45 HIGH | 34 MEDIUM | 20 MEDIUM | 7 LOW | 18 MEDIUM |
| **STRONG** | 15 MEDIUM | 11 LOW | 7 LOW | 2 INFO | 6 LOW |
| **INTERNAL** | 5 LOW | 4 INFO | 2 INFO | 1 INFO | 2 INFO |

---

## 5. Condition-strength rubrics

Each rubric is a pure function of the `Principal` and `Condition` elements. The
rubric identifier appears on every finding (`exposure.rubric`) so a grade can be
traced to the code that produced it.

### 5.0 The gate every rubric runs behind: does the condition evaluate at all?

Before any provider-specific logic, `conditions.analyze_key()` decides whether
a condition on a given key is a *guard* or decoration. A condition is **not** a
guard when:

| Weakness code | Cause | Documented basis |
|---|---|---|
| `if_exists_vacuous` | `...IfExists` on a claim the provider does not always issue, with no `Null: {key: "false"}` companion | "If the key is not present, evaluate the condition element as true." |
| `forallvalues_vacuous` | `ForAllValues:` with no `Null` companion | "ForAllValues returns true if there are no context keys in the request." |
| `negated_operator_only` | Only a `StringNotEquals`-family operator on the key | Negated operators evaluate true on an absent key and exclude rather than pin. |
| `wildcard_only_value` | The only value is `*` or `?` | Carries no information. |
| `unreadable_condition_value` | The value was not a string or list of strings | Cannot be evaluated. |

And two that are reported without changing the grade:

| Code | Meaning |
|---|---|
| `if_exists_redundant` | `IfExists` on a claim that is always issued. Untidy, not a hole. |
| `literal_wildcard_in_exact_operator` | A `*` under `StringEquals`. Compared literally, so the statement can never match: a **fail-closed defect**, reported separately from exposure. |

### 5.1 OIDC / CI federation — `oidc.*`

The rubric grades on how many *dimensions of the caller's identity* the
conditions actually pin, then maps that to a grade differently depending on
whether the issuer is shared or private.

Dimensions:

* **tenant** — the GitHub organisation, GitLab group, Terraform organisation,
  Kubernetes cluster.
* **project** — the repository, workspace or namespace.
* **workload** — the branch, tag, environment, reusable workflow or service
  account.

Level = 3 if project **and** workload; 2 if project; 1 if tenant; else 0.

| Level | Shared issuer | Private issuer |
|---:|---|---|
| 0 | `OPEN` | `MODERATE` |
| 1 | `WEAK` | `MODERATE` |
| 2 | `MODERATE` | `MODERATE` |
| 3 | `STRONG` | `STRONG` |

The private-issuer floor is the point of the whole rubric: on a private issuer,
only that one organisation can mint a token, so a missing subject condition is
sloppy rather than open. On a shared issuer, every other customer of that SaaS
mints tokens from the identical URL.

**Two rules that prevent wrong grades:**

* **Conditions are AND-ed, so pinned dimensions are the union across all
  conditions.** This is why AWS's own recommended trust policy - which pins
  `repository_owner_id`, `repository_id`, `actor_id` and `ref` and has no `sub`
  condition - grades `STRONG` and not `OPEN`.
* **Values within one condition are OR-ed, so the weakest value governs.**
  `["repo:acme/app:ref:refs/heads/main", "repo:acme/*"]` grades on the second
  value, not the first. Getting this backwards would make a wildcard invisible.

**`oidc.github_actions`** parses the default subject grammar
`repo:<org>/<repo>:<selector>` and credits the documented non-`sub` claims:

| Claim | Dimension credited | Note |
|---|---|---|
| `repository_owner_id`, `enterprise_id`, `repository_owner` | tenant | `repository_owner` is not in AWS's documented mapping; flagged |
| `repository`, `repository_id` | project (+ tenant) | `repository` with a wildcard credits tenant only |
| `job_workflow_ref` | project + workload | Parsed as `<org>/<repo>/...` |
| `ref`, `environment`, `workflow`, `actor`, `actor_id` | workload | `environment` is only issued when the job declares one |

A `pull_request` selector credits **project only**: every pull request in the
repository satisfies it.

`github_mutable_identifiers_only` is reported when nothing immutable is pinned,
with AWS's rename-and-reclaim warning quoted. It does **not** change the grade,
because AWS's baseline recommendation is name-based and downgrading it would
flag correct policies.

**`oidc.eks_irsa`** grades subject specificity by counting pinned
`:`-delimited segments: ≥4 (namespace **and** service account) is fully pinned,
3 pins the namespace only, fewer pins nothing.

**`oidc.shared_issuer`** requires the tenancy claim AWS documents for that
issuer; missing ⇒ `OPEN`. Present ⇒ graded by the structural segment heuristic,
with the heuristic disclosed in the finding's limitations.

**`oidc.private_issuer`** grades structurally with the private-issuer floor, and
carries a limitation saying that if the issuer is in fact a multi-tenant SaaS
that AWS has not catalogued, the real exposure is higher.

### 5.2 Cross-account — `aws.cross_account`

Baseline from how broad the named principal is:

| Principal | Baseline |
|---|---|
| Account root (`123456789012` or `...:root`) | `WEAK` — every user and role in that account is a candidate |
| A specific role/user ARN | `MODERATE` |

Then adjusted:

| Signal | Effect |
|---|---|
| Account in `trusted_account_ids` | `MODERATE` (root) / `STRONG` (named), and not treated as a third party |
| `sts:ExternalId` required with a value that passes the guessability checks | one step towards STRONG |
| `sts:ExternalId` required but weak | no improvement; `external_id_weak_value` |
| No `sts:ExternalId` on a third-party relationship | `external_id_missing` |
| `aws:PrincipalArn` pinned exactly | `STRONG` |
| `aws:PrincipalArn` pinned with a pattern | one step towards STRONG |
| `aws:PrincipalOrgID` pinned | one step towards STRONG |

External-ID guessability checks, in order — any hit means weak:

1. Bare wildcard, or contains a wildcard under `StringLike`.
2. In the placeholder denylist (`changeme`, `secret`, `test`, `example`, …).
3. Equal to your account id or the trusted account's id.
4. Derived from the role name (substring either way, for role names ≥ 4 chars).
5. Contains the vendor name from the mapping — AWS: "do not use something that
   can be guessed, like the name … of the third party".
6. Shorter than 16 characters. AWS's API floor is 2, which is not a useful bar.
7. All digits — suggests a sequential customer number.
8. A single character class — entropy far below what the length implies.

TrustEdge never claims to know that the third party generated the value or that
it is unique per tenant. The finding says so.

### 5.3 Wildcard principal — `aws.wildcard_principal`

`Principal: "*"` is bounded only by conditions, and only by conditions on an
**identity** key.

| Condition present | Grade |
|---|---|
| None | `OPEN` |
| `aws:PrincipalArn` pinned exactly | `STRONG` |
| `aws:PrincipalOrgID`, `aws:PrincipalOrgPaths`, `aws:PrincipalAccount` | `MODERATE` |
| `aws:PrincipalTag/*` | `WEAK` — tags in the caller's account are set by that account's admins |
| Only `sts:ExternalId` | `WEAK` — AWS: "AWS does not treat the external ID as a secret" |
| Only contextual keys (`aws:SourceIp`, `aws:SourceVpc`, …) | `WEAK` — they restrict *how*, not *who* |
| Only unrecognised keys | `OPEN`, with a limitation saying unrecognised keys are not credited |

An identity key present but neutralised (`IfExists`, `ForAllValues`) leaves the
grade at `OPEN`, and the finding says the condition is written but not in
force.

### 5.4 AWS service principals — `aws.service_principal`

Two paths, because a `Service` principal is not always an inbound boundary.

**Compute attachment** (`ec2`, `lambda`, `ecs-tasks`, `pods.eks`, `eks`,
`codebuild`, `states`, `glue`, `sagemaker`, `batch`, `apprunner` ×3, `ssm`,
`cloudformation`, `eks-nodegroup`, `elasticmapreduce`): the statement exists so
your own workload can obtain credentials. Graded `INTERNAL`, with the finding
pointing at `iam:PassRole` and the service's own create/update permissions as
the real control. The list is a named table in `providers/aws.py` so it can be
reviewed and edited; anything not on it takes the second path.

**Everything else** is a confused-deputy question:

| Condition | Grade |
|---|---|
| `aws:SourceAccount` / `aws:SourceArn` pinned to your own account | `STRONG` |
| Pinned to a different account | `MODERATE`, flagged for confirmation |
| `aws:SourceOrgID` / `aws:SourceOrgPaths` | `MODERATE` |
| Account segment wildcarded or unparsable | `WEAK` |
| No source condition | `MODERATE` + `service_principal_no_source_condition`, with an explicit limitation that support varies by service |

Cognito's identity-pool service principal with no conditions is a documented
special case and grades `OPEN`.

### 5.5 SAML — `saml.federation`

| Conditions | Grade |
|---|---|
| A subject-identifying key (`saml:sub`, `saml:namequalifier`, `saml:uid`, …) | `STRONG` |
| A group/affiliation attribute | `MODERATE` |
| Only `saml:aud` | `MODERATE` + `saml_no_subject_condition` |
| None | `WEAK` + `saml_no_conditions` |

`WEAK` rather than `OPEN` because possession of an assertion from that specific
IdP is already a bound - just not one IAM is enforcing. Every SAML finding
carries the limitation that the IdP's own role-assignment rules are invisible
and are usually the real access control.

### 5.6 IAM Roles Anywhere — `roles_anywhere`

Two halves, and STRONG needs both:

| Trust anchor pinned (`aws:SourceArn`) | Certificate identity pinned | Grade |
|---|---|---|
| yes | yes | `STRONG` |
| yes | no | `MODERATE` |
| no | yes | `MODERATE` — a CN is only unique within a CA |
| no | no | `WEAK` |

Also checked: the three actions AWS documents as required. A statement missing
`sts:TagSession` or `sts:SetSourceIdentity` is reported as a fail-closed defect.

---

## 6. Blast radius {#blast-radius}

### 6.1 Administrator-equivalent

* `Action: "*"` with `Resource: "*"`.
* A `NotAction`-only Allow on `Resource: "*"` whose exclusion list still leaves
  `iam:PutRolePolicy` reachable. (A `NotAction` of `iam:*` is broad but not
  admin-equivalent, and is graded accordingly.)
* Both `iam:PutRolePolicy` and `iam:AttachRolePolicy` on `Resource: "*"` in one
  statement — which `iam:*` satisfies. The role can grant itself anything.

### 6.2 Escalation primitives

High-weight — each grants the holder permissions it was not given:

`iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`,
`iam:AttachRolePolicy`, `iam:AttachUserPolicy`, `iam:AttachGroupPolicy`,
`iam:PutRolePolicy`, `iam:PutUserPolicy`, `iam:UpdateAssumeRolePolicy`,
`iam:CreateAccessKey`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`,
`iam:AddUserToGroup`, `kms:PutKeyPolicy`, `s3:PutBucketPolicy`,
`lambda:UpdateFunctionCode`, `ssm:SendCommand`, `ssm:StartSession`.

Moderate-weight — dangerous in combination rather than alone:

`iam:PassRole`, `iam:CreateRole`, `sts:AssumeRole`, `sts:GetFederationToken`,
`lambda:CreateFunction`, `ec2:RunInstances`, `cloudformation:CreateStack`,
`codebuild:CreateProject`, `ecs:RegisterTaskDefinition`,
`glue:CreateDevEndpoint`, `sagemaker:CreateNotebookInstance`,
`datapipeline:CreatePipeline`.

Combinations detected explicitly:

* `passrole_plus_compute` — `iam:PassRole` with any compute-creation action.
  This is the one that matters: passing a role only becomes code execution when
  something runs code.
* `create_role_plus_policy` — `iam:CreateRole` with `iam:AttachRolePolicy` or
  `iam:PutRolePolicy`.

### 6.3 Data-plane reach

`secretsmanager:GetSecretValue`, `kms:Decrypt`, `rds-data:ExecuteStatement`,
`rds:RestoreDBInstanceFromDBSnapshot`, `ec2:ModifySnapshotAttribute` are
high-weight; `s3:GetObject`/`PutObject`/`DeleteObject`, `dynamodb:Scan`,
`dynamodb:PutItem`, `ssm:GetParameter`, `ses:SendEmail` are moderate;
`logs:FilterLogEvents`, `ecr:BatchGetImage`, `sqs:ReceiveMessage` are low.

Service-wide wildcards (`s3:*`, `secretsmanager:*`, `kms:*`, `dynamodb:*`,
`rds:*`, `ssm:*`, `sqs:*`, `sns:*`, `ecr:*`, `logs:*`) are recorded separately,
because a wildcard's reach grows automatically as AWS adds actions.

### 6.4 What is implemented, approximated and not evaluated

**Implemented:** Allow statements from inline and resolvable managed policies;
IAM glob action matching (`*`, `?`, case-insensitive); `NotAction` as
"everything except"; resource breadth (`*` versus a named ARN).

**Approximated:** Deny handling. Only an *unconditional* `Deny` on
`Resource: "*"` suppresses a capability. Conditional and resource-scoped denies
are counted and disclosed but not applied — guessing whether a scoped deny
covers the resource an attacker would choose trades false positives for false
negatives, which is the worse trade here.

**Not evaluated at all**, and stated on every finding: permissions boundaries,
service control policies, resource control policies, session policies,
resource-based policies in other accounts, group membership, and conditions on
Allow statements.

The consequence, spelled out in the report: `HIGH` or `ADMIN` means *the role's
own policies grant these capabilities*, not that an attacker has been proven
able to use them.

---

## 7. Ranking determinism

Findings sort by `(-risk_score, severity_rank, role_name, statement_index,
principal)`. The same input always produces the same order, and
`finding_id` is derived from the role, statement index, principal position and
principal value — never from rank — so IDs are stable across runs and across
rubric changes that alter ordering.

---

## 8. Changing a rule

1. Find or add the primary source. If there isn't one, the rule doesn't ship.
2. Add the quotation and the URL to `docs/research.md`, in the verified or the
   inferred table as appropriate.
3. Change the rubric, and the weight table here if the arithmetic moved.
4. Add a fixture that exercises it, and a test that asserts the *AWS semantic*
   rather than the implementation's return value.
5. Re-run `pytest`.
