# TrustEdge research record

**Purpose of this document.** Every grading rule in TrustEdge is supposed to be
traceable to a primary source. This file is that trace. It also records, just
as explicitly, the claims that could **not** be verified and were therefore
removed from the project rather than repeated.

**Verification method and date.** The AWS documentation pages linked below were
fetched and read on **2026-09-07** while building the analyser. Quotations are
copied verbatim from those pages. Where a page's own wording is ambiguous or
self-contradictory, that is recorded rather than smoothed over.

**A note on what verification means here.** "Verified" below means *the primary
documentation says this*. It does not mean the behaviour was tested against a
live AWS account. TrustEdge is an offline tool and the analyser's rules are
built from documented semantics; where documented semantics and observed
behaviour could diverge, the finding says so.

---

## 1. Executive summary

Every AWS account accumulates doors that open from outside it: vendor
cross-account roles, SAML federation, OIDC/CI federation, EKS workload
identity, IAM Roles Anywhere, and AWS service principals. The security of each
door lives in a small, rarely-reviewed `AssumeRolePolicyDocument`.

Two things make those documents worth a dedicated tool:

1. **A condition can look like a guard and enforce nothing.** AWS documents
   that `...IfExists` operators evaluate to *true* when the key is absent, and
   that `ForAllValues` "returns true if there are no context keys in the
   request". A trust policy with `StringEqualsIfExists` on a claim the identity
   provider does not always issue is unguarded, and reads as guarded.
2. **The same omission means different things on different providers.** A
   missing subject condition on `token.actions.githubusercontent.com` - an
   issuer URL that is *identical for every GitHub customer* - lets a stranger's
   workflow in. The same omission on an EKS cluster's own OIDC endpoint bounds
   the caller to that cluster. AWS itself draws this line, calling the first
   kind of issuer "shared" and the second "private".

Combining those two observations with the role's resolved permissions -
exposure × blast radius - is what TrustEdge does. It is not a new security
primitive; it is a focused artifact built out of documented ones.

---

## 2. Security problem

A trust policy is a resource-based policy attached to an IAM role. It answers
*who may become this identity*. It is separate from, and evaluated separately
from, the role's permission policies, which answer *what this identity may
do*.

Three properties of that arrangement create the problem:

* **The role ARN is not a secret.** AWS says so directly about the related
  external ID: "AWS does not treat the external ID as a secret... The external
  ID for a role can be seen by anyone with permission to view the role."
  Nothing about a role ARN or an external ID constitutes authentication.
* **Trust decays silently.** A relationship that was correct when a contract
  was signed remains in the policy after the contract lapses, the vendor is
  acquired, or the CI provider changes its token format. Nothing in IAM
  expires a trust statement.
* **The blast radius is set elsewhere.** The person tightening a trust policy
  and the person attaching `AdministratorAccess` are frequently different
  people at different times, so the pairing that actually matters - a weak door
  on a powerful role - is nobody's single view.

---

## 3. Threat model

Summarised here; the full version is in [threat-model.md](threat-model.md).

**In scope.** An external identity - another AWS account's principal, a
workflow in a CI provider's shared tenancy, a holder of an X.509 certificate, a
user of a federated IdP - obtains valid AWS credentials in the target account
by calling an STS assume-role API against a role whose trust policy admits
them, and then uses the role's permissions.

**Out of scope.** Compromise of the identity provider itself; compromise of a
legitimately trusted vendor; intra-account privilege escalation between
principals that are already inside; anything requiring code execution in the
account.

**Assumed attacker capability.** Can enumerate or guess role ARNs (they are not
secret), can obtain a token from any *shared* identity provider by being an
ordinary customer of it, and can create a repository, branch, workspace or
service account within their own tenancy of that provider.

---

## 4. AWS trust-policy semantics (verified)

### 4.1 Condition evaluation with a missing key

From *IAM JSON policy elements: Condition operators*:

> If the key that you specify in a policy condition is not present in the
> request context, the values do not match and the condition is *false*. If the
> policy condition requires that the key is *not* matched, such as
> `StringNotLike` or `ArnNotLike`, and the right key is not present, the
> condition is *true*. This logic applies to all condition operators except
> ...IfExists and Null check.

And for `...IfExists`:

> You do this to say "If the condition key is present in the context of the
> request, process the key as specified in the policy. If the key is not
> present, evaluate the condition element as true."

And for `ForAllValues`:

> The `ForAllValues` qualifier returns true if there are no context keys in the
> request or if the context key value resolves to a null dataset.

**How TrustEdge uses this.** `analyze_key()` in `conditions.py` treats an
`...IfExists` or `ForAllValues` condition as *not a guard* unless a
`Null: {key: "false"}` check pins the key as present, or the claim is one an
OIDC ID token always carries. Findings carry the weakness codes
`if_exists_vacuous` and `forallvalues_vacuous`.

Source:
<https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html>

### 4.2 Wildcards are operator-dependent

`StringEquals` is documented as "Exact matching, case sensitive".
`StringLike` values "can include multi-character match wildcards (\*) and
single-character match wildcards (?) anywhere in the string. You must specify
wildcards to achieve partial string matches." `ArnEquals` and `ArnLike`
"behave identically" and both support wildcards per ARN component.

**How TrustEdge uses this.** A `*` in a `StringEquals` value is compared as a
literal character, so the statement can never match a real request. TrustEdge
reports this as a **fail-closed defect** (`literal_wildcard_in_exact_operator`)
and says explicitly that the policy is broken rather than permissive - because
the author's intended restriction is not being enforced anywhere either.

### 4.3 Cross-account requests need both sides

From *Cross account resource access in IAM*:

> In cross account access, a principal needs an `Allow` in the identity policy
> **and** the resource-based policy.

And from *Cross-account policy evaluation logic*:

> When you make a cross-account request, AWS performs two evaluations. AWS
> evaluates the request in the trusting account and the trusted account... The
> request is allowed only if both evaluations return a decision of `Allow`.

**How TrustEdge uses this.** Every cross-account finding carries a limitation
saying TrustEdge sees only your side, so a finding describes *reachability from
your account's perspective*, not a proven path. This is the single most
important reason TrustEdge never claims a role "is exploitable".

Sources:
<https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies-cross-account-resource-access.html>,
<https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html>

### 4.4 `sts:ExternalId`

From *IAM and AWS STS condition context keys* and *Access to AWS accounts owned
by third parties*:

* "The primary function of the external ID is to address and prevent the
  confused deputy problem."
* "The `ExternalId` value must have a minimum of 2 characters and a maximum of
  1,224 characters. The value must be alphanumeric without white space. It can
  also include the following symbols: plus (+), equal (=), comma (,), period
  (.), at (@), colon (:), forward slash (/), and hyphen (-)."
* "AWS does not treat the external ID as a secret."
* "The external ID can be any identifier that is known only by you and the
  third party. For example, you can use an invoice ID between you and the third
  party, but do not use something that can be guessed, like the name or phone
  number of the third party."
* "What is crucial is that it must be generated by Example Corp and ***not***
  their customers to ensure each external ID is unique."
* "In a multi-tenant environment where you support multiple customers with
  different AWS accounts, we recommend using one external ID per AWS account.
  This ID should be a random string generated by the third party."

**How TrustEdge uses this.** `_assess_external_id()` in `providers/aws.py`
checks for wildcards, placeholder values, AWS account ids, the role name, the
vendor name, length below 16 characters, all-digit values, and single
character-class values. It does **not** claim to verify that the third party
generated the value or that it is unique per tenant - the finding says so.

Because AWS states the external ID is not a secret, TrustEdge grades
`Principal: "*"` guarded only by `sts:ExternalId` as **WEAK**, not STRONG.

Sources:
<https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html>,
<https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html>

### 4.5 Confused deputy and the source condition keys

From *The confused deputy problem*:

> When an AWS service principal from a calling service is accessing a resource
> from a called service, the resource policy from the called service is only
> authorizing the AWS service principal, and not the actor who configured the
> calling service.

> We recommend using `aws:SourceArn`, `aws:SourceAccount`, `aws:SourceOrgID`,
> or `aws:SourceOrgPaths` in your resource policies wherever an AWS service
> principal is granted permission to access one of your resources.

And, importantly for false-positive control:

> Please see the documentation of the services you use for more information
> about service-specific mechanisms that can help avoid cross-service confused
> deputy risks, and whether `aws:SourceArn`, `aws:SourceAccount`,
> `aws:SourceOrgID`, and `aws:SourceOrgPaths` are supported.

**How TrustEdge uses this.** A `Service` principal with no source condition is
graded MODERATE and reported as a *review item*, with an explicit limitation
that support varies by service and that TrustEdge is not claiming the role is
reachable from another account. See §8 for the compute-attachment carve-out.

Source: <https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html>

---

## 5. Provider-specific research

### 5.1 Private versus shared OIDC issuers (verified)

This is the distinction the whole OIDC rubric turns on. From *Identity-provider
controls for shared OIDC providers*:

> A private OIDC IdP can be owned and managed by a single organization or can be
> a tenant of a SaaS provider, with its OIDC Issuer URL serving as a unique
> identifier specific to that organization. In contrast, a shared OIDC IdP is
> utilized across multiple organizations, where the OIDC Issuer URL might be
> identical for all organizations using that shared identity provider.

AWS now enforces a tenancy-claim condition at policy-write time for recognised
shared issuers:

> For recognized shared OpenID Connect (OIDC) identity providers (IdPs), IAM
> requires explicit evaluation of specific claims in role trust policies. These
> required claims, called *identity-provider controls*, are evaluated by IAM
> during role creation and trust policy updates. If the role trust policy does
> not evaluate the controls required by the shared OIDC IdP, the role creation
> or update would fail.

And - the reason an offline audit of deployed policies still has value:

> Identity-provider controls will not be evaluated by IAM for existing OIDC role
> trust policies.

**How TrustEdge uses this.** `SHARED_OIDC_PROVIDERS` in `providers/oidc.py`
encodes AWS's table of shared issuers and the tenancy claim each one requires.
An unguarded tenancy claim on a shared issuer is OPEN; the same on a private
issuer floors at MODERATE. Every OPEN GitHub finding states that AWS would now
refuse to create the policy but does not retroactively evaluate existing ones.

The issuers and required claims TrustEdge carries, verbatim from that table:
Amazon Cognito (`aud`), Azure Sentinel (`sts:RoleSessionName`), Buildkite
(`sub`), Codefresh SaaS (`sub`), DVC Studio (`sub`), GitHub Actions (`sub`),
GitHub audit log streaming (`sub`), GitHub vstoken (`sub`), GitLab (`sub`), IBM
Turbonomic SaaS (`sub`, six issuer URLs), Pulumi Cloud (`aud`),
sandboxes.cloud (`aud`), Scalr (`sub`), Shisho Cloud (`sub`), HCP Terraform
(`sub`), Upbound (`sub`), Vercel (`aud`).

A second, smaller table (`SHARED_BY_INSPECTION`) holds issuers that are plainly
multi-tenant but are not in AWS's controls table - CircleCI, Google, Login with
Amazon, Facebook. Findings record which table a decision came from, so a
reviewer can weigh them differently.

Source:
<https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc_secure-by-default.html>

### 5.2 GitHub Actions OIDC (verified against AWS; see §7 for the GitHub-side gap)

**Which claims AWS actually evaluates.** *Available keys for AWS OIDC
federation* has a per-provider mapping. The GitHub tab documents exactly these
AWS STS condition keys: `actor`, `actor_id`, `job_workflow_ref`, `repository`,
`repository_id`, `repository_owner_id`, `workflow`, `ref`, `environment`,
`enterprise_id`. The Default tab, which AWS says GitHub uses, adds `aud`,
`sub`, `amr`, `email`, `oaud`. All the GitHub-specific keys are marked "Available
in session: No", meaning they can be used in the role trust policy for the
initial `AssumeRoleWithWebIdentity` call and not afterwards.

Two consequences TrustEdge acts on:

* `repository_owner` (the organisation **name**) is *not* in AWS's documented
  list, although `repository_owner_id` is. TrustEdge flags condition keys
  outside the documented mapping as `undocumented_condition_key` with an
  explicit statement that it cannot confirm whether AWS populates the key -
  and notes that under a plain operator such a condition fails closed, while
  under `IfExists` it enforces nothing. It does **not** assert the key is
  invalid.
* `environment` is not always issued. AWS: "If the environment claim is
  included in your trust policy, an environment must be configured and provided
  in the GitHub workflow." So `StringEqualsIfExists` on `:environment` is
  genuinely vacuous, and TrustEdge says so.

**Subject format.** AWS's own example uses
`repo:<org>/<repo>:ref:refs/heads/<branch>` and describes it as "the default
subject value format documented by GitHub". Because GitHub permits the subject
template to be customised, TrustEdge parses that shape and reports anything
else as a custom template rather than guessing at it.

**AWS's warnings, quoted.**

> If you do not limit the condition key `token.actions.githubusercontent.com:sub`
> to a specific organization or repository, then GitHub Actions from
> organizations or repositories outside of your control are able to assume roles
> associated with the GitHub IAM IdP in your AWS account.

> When GitHub's OIDC IdP is the trusted Principal for your role, IAM checks the
> role trust policy condition to verify that the condition key
> `token.actions.githubusercontent.com:sub` is present and that its value is not
> solely a wildcard character (\* and ?) or null. IAM performs this check when
> the trust policy is created or updated.

> We recommend that you limit the condition to a specific set of repositories or
> branches within your GitHub organization.

**Mutable versus immutable claims.** AWS:

> On GitHub, repository, organization, and user names can change. A name that is
> freed by renaming or deletion can be claimed by a different account. Policies
> that rely solely on mutable name-based claims (such as `repository` or
> `actor`) could grant access to unintended identities. To help protect against
> this, use the immutable identifiers that GitHub provides, such as
> `repository_id`, `repository_owner_id`, or `actor_id`, in your role trust
> policies or resource control policies.

TrustEdge reports `github_mutable_identifiers_only` when a policy pins only
name-based claims. Deliberately, this does **not** change the exposure grade:
AWS's own baseline recommendation is name-based, so downgrading it would flag
correct policies. It is reported as a hardening gap with the citation attached.

**One documented inconsistency, recorded rather than resolved.** AWS's
"use immutable identifiers" example trust policy pins `repository_owner_id`,
`repository_id`, `actor_id`, `ref` and `enterprise_id` and contains **no**
`sub` condition - which appears to conflict with the identity-provider control
requiring `sub` for that issuer. TrustEdge handles this by grading on the
*union of pinned dimensions* across all conditions rather than on `sub` alone,
so AWS's own recommended policy grades STRONG. This is an inference from two
documented facts, not a documented behaviour; it is flagged as an inference in
§7.

Sources:
<https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html>,
<https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html>

### 5.3 HCP Terraform (verified, and stricter than GitHub)

> IAM roles for HashiCorp Cloud Platform (HCP) Terraform OIDC provider must
> evaluate the IAM condition key, `app.terraform.io:sub`, in the role trust
> policy... Additionally, AWS STS will deny authorization requests if your role
> trust policy doesn't evaluate this condition key.

Note the difference from GitHub: for Terraform, AWS states enforcement at *STS
request time*, not only at policy-write time. TrustEdge still reports a missing
tenancy claim, because the export cannot tell you when the policy was written
and the finding is cheap to verify.

### 5.4 Amazon Cognito (verified)

> IAM roles for Amazon Cognito identity pools trust the service principal
> `cognito-identity.amazonaws.com` to assume the role. Roles of this type must
> contain at least one condition key to limit the principals who can assume the
> role... A policy that trusts Amazon Cognito identity pools without this
> condition creates a risk that a user from an unintended identity pool can
> assume the role.

TrustEdge grades a Cognito trust with no conditions as OPEN and cites this.

### 5.5 EKS / IRSA (verified in structure, inferred in subject format)

*IAM roles for service accounts* documents that Amazon EKS "hosts a public OIDC
discovery endpoint for each cluster", that the projected token is "an OIDC JSON
web token that also contains the service account identity and supports a
configurable audience", and warns:

> Containers are not a security boundary, and the use of IAM roles for service
> accounts does not change this.

The per-cluster issuer is what makes an EKS OIDC provider **private** in AWS's
taxonomy: only workloads in that cluster can obtain a token from it. TrustEdge
therefore floors a missing subject condition at MODERATE rather than OPEN, and
grades subject specificity structurally by counting pinned `:`-delimited
segments. The `system:serviceaccount:<namespace>:<serviceaccount>` subject
shape is treated as a convention TrustEdge recognises, and the exact format was
**not** re-verified from primary documentation in this build - see §7.

EKS Pod Identity (`pods.eks.amazonaws.com`) is handled separately: the binding
between role, namespace and service account is a pod identity association,
which is not present in an IAM export at all, so TrustEdge grades it INTERNAL
and says where the real control lives.

Source:
<https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html>

### 5.6 SAML 2.0 (verified)

*Available keys for SAML-based AWS STS federation* lists the trust-policy keys:
`saml:aud`, `saml:iss`, `saml:sub`, `saml:sub_type`, `saml:namequalifier`,
`saml:doc`, and a long list of `eduPerson`/`eduOrg` and directory attributes.
Two details TrustEdge acts on:

* `saml:aud` "An endpoint URL to which SAML assertions are presented. The value
  for this key comes from the `SAML Recipient` field in the assertion, *not*
  the `Audience` field." It restricts the assertion's recipient, **not** the
  user - so a trust policy with only `saml:aud` places no limit on *which*
  federated user takes the role. That is graded MODERATE with
  `saml_no_subject_condition`.
* `saml:sub_type` "can have the value `persistent`, `transient`... A value of
  `persistent` indicates that the value in `saml:sub` is the same for a user
  between sessions. If the value is `transient`, the user has a different
  `saml:sub` value for each session." TrustEdge points out that a transient
  subject cannot be pinned reliably.
* AWS also notes: "No other SAML-based federation condition keys are available
  for use after the initial external identity provider (IdP) authentication
  response." TrustEdge carries this as a limitation on every SAML finding.

### 5.7 IAM Roles Anywhere (verified)

From *The IAM Roles Anywhere trust model*:

> To use an IAM role with IAM Roles Anywhere, you must create a trust
> relationship with the IAM Roles Anywhere service principal
> `rolesanywhere.amazonaws.com`... The policy must grant the permissions:
> `sts:AssumeRole`, `sts:SetSourceIdentity`, `sts:TagSession`.

> IAM Roles Anywhere extracts values from the subject, issuer, and Subject
> Alternative Name (SAN) fields of the authenticating certificate and makes them
> available for policy evaluation via the sourceIdentity and principal tags.

> In general, it is strongly recommended that you use the `aws:SourceArn` or the
> `aws:SourceAccount` global condition keys or the `sts:SourceIdentity`
> condition key in your role trust policies. This combination of conditions
> implements least privilege permissions and prevents IAM Roles Anywhere from
> acting as a potential confused deputy... the `aws:SourceArn` and
> `aws:SourceAccount` will be set based on the ARN of the trust anchor specified
> in the call to `CreateSession`.

The tag names are documented with worked examples:
`aws:PrincipalTag/x509Subject/CN`, `aws:PrincipalTag/x509Issuer/CN`,
`aws:PrincipalTag/x509SAN/DNS`, `aws:PrincipalTag/x509SAN/URI`,
`aws:PrincipalTag/x509SAN/Name/CN`.

**The insight TrustEdge encodes.** A certificate common name is only unique
*within a certificate authority*. A condition on
`aws:PrincipalTag/x509Subject/CN` with no `aws:SourceArn` condition is
satisfied by a certificate with that CN issued by **any** trust anchor
configured in the account - so adding a trust anchor anywhere in the account
silently widens the role's trust. TrustEdge grades certificate-only and
anchor-only conditions as MODERATE and requires both for STRONG.

**A documentation ambiguity, recorded not resolved.** The same page states that
certificate-derived values "need to match the pattern defined in STS session
tags. The service ignores values that do not match this pattern. **You cannot
use these values in policy conditions.**" - immediately before presenting
several trust policies that use exactly those values in conditions. TrustEdge
follows the worked examples and carries a limitation telling the reader to
confirm current behaviour before relying on a certificate-attribute condition
as the only control.

Also verified and used: revocation is CRL-import-only - "Callbacks to CRL
Distribution Points (CDPs) or Online Certificate Status Protocol (OCSP)
endpoints are not supported" - which is why the STRONG recommendation mentions
keeping imported CRLs current.

Source:
<https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html>

### 5.8 GitLab, CircleCI, Buildkite and other shared issuers

AWS's controls table tells us *which* claim must be evaluated for each of these
issuers. It does not document the *grammar* of those claims. TrustEdge
therefore grades them with a structural heuristic - counting fully pinned
`:`/`/`-delimited segments in the subject - and every such finding carries the
limitation "TrustEdge has no bespoke grammar for this provider's `sub` claim,
so the grade comes from counting fully pinned segments rather than from
understanding the claim's meaning."

The GitLab subject grammar (`project_path:...:ref_type:...:ref:...`) was **not**
verified from GitLab's primary documentation in this build, so no bespoke
GitLab parser was written. Writing one from memory is exactly the failure mode
this project is supposed to avoid.

---

## 6. Blast-radius research

The escalation primitives TrustEdge detects are drawn from documented IAM
behaviour, not from a wordlist.

`iam:PassRole` is the anchor. AWS:

> When setting the `PassRole` permission, you should make sure that a user
> doesn't pass a role where the role has more permissions than you want the user
> to have. For example, Alice might not be allowed to perform any Amazon S3
> actions. If Alice could pass a role to a service that allows Amazon S3
> actions, the service could perform Amazon S3 actions on behalf of Alice when
> executing the job.

Also verified and used in the report text:

> `PassRole` is not an API call. `PassRole` is a permission, meaning no
> CloudTrail logs are generated for IAM `PassRole`.

That is why TrustEdge treats `iam:PassRole` **alone** as MODERATE and
`iam:PassRole` **plus a compute-creation action** as HIGH: passing a role only
becomes code execution when combined with something that runs code. The
compute-creation set is `lambda:CreateFunction`, `ec2:RunInstances`,
`cloudformation:CreateStack`, `codebuild:CreateProject`,
`ecs:RegisterTaskDefinition`, `glue:CreateDevEndpoint`,
`sagemaker:CreateNotebookInstance`, `datapipeline:CreatePipeline`,
`ssm:SendCommand`.

The policy-mutation primitives - `iam:CreatePolicyVersion`,
`iam:SetDefaultPolicyVersion`, `iam:AttachRolePolicy`, `iam:PutRolePolicy`,
`iam:UpdateAssumeRolePolicy`, `iam:CreateAccessKey`, `iam:CreateLoginProfile`,
`iam:AddUserToGroup` - are HIGH on their own because each one grants the holder
the ability to give itself permissions it was not granted. `iam:UpdateAssumeRolePolicy`
deserves special mention: it lets a principal rewrite the very objects this
tool analyses.

The full detection table with per-capability rationale is in
[methodology.md](methodology.md#blast-radius).

Source: <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html>

---

## 7. What is verified, what is inferred, what was removed

### Verified from primary AWS documentation

| Claim | Where it is used |
|---|---|
| Missing key + normal operator ⇒ condition false | `conditions.py` |
| Missing key + `...IfExists` ⇒ condition true | `if_exists_vacuous` |
| `ForAllValues` returns true on an absent/empty key | `forallvalues_vacuous` |
| `StringEquals` does not interpret `*`; `StringLike` does | `literal_wildcard_in_exact_operator` |
| `ArnEquals` and `ArnLike` behave identically, wildcards allowed per component | Roles Anywhere and service rubrics |
| Cross-account access needs an Allow in both the identity and resource policy | Every cross-account finding's limitations |
| External ID is not a secret; must be generated by the third party; charset and length bounds | `_assess_external_id` |
| Confused-deputy source keys and the "varies by service" caveat | Service-principal rubric |
| Private vs shared OIDC issuer taxonomy; shared-issuer table and required claims | `SHARED_OIDC_PROVIDERS` |
| Identity-provider controls are not applied to pre-existing trust policies | Every OPEN OIDC finding |
| AWS's documented GitHub claim→condition-key mapping | `GITHUB_DOCUMENTED_CLAIMS` |
| GitHub names are mutable and reclaimable; immutable id claims exist | `github_mutable_identifiers_only` |
| GitHub `environment` claim is only present when the workflow declares one | `if_exists_vacuous` on `:environment` |
| Cognito identity-pool roles must carry at least one condition | `cognito_role_without_condition` |
| `saml:aud` is the Recipient, not the Audience, and does not restrict the user | `saml_no_subject_condition` |
| `saml:sub_type` transient/persistent semantics | SAML reasoning |
| Only `saml:namequalifier`/`sub`/`sub_type` survive the initial IdP response | SAML limitations |
| Roles Anywhere required actions, x509 principal tags, `aws:SourceArn` = trust anchor | Roles Anywhere rubric |
| Roles Anywhere revocation is imported-CRL only | Roles Anywhere recommendation |
| `iam:PassRole` risk and its absence from CloudTrail | Blast-radius details |
| IAM Access Analyzer's external-access scope, resource types and per-Region behaviour | Positioning, §9 |

### Inferences (reasoned from verified facts, not documented as such)

1. **Grading on the union of pinned dimensions rather than on `sub` alone.**
   Derived from AWS's immutable-identifier example coexisting with the
   identity-provider control. Reasonable, and it prevents flagging AWS's own
   guidance - but it is our reading, not AWS's statement.
2. **The exposure weights and severity bands.** `docs/methodology.md` explains
   them; they are a defensible ordering, not an AWS-published risk model.
3. **The external-ID guessability heuristics** (16-character floor, character
   classes, all-digits). AWS says "not guessable" and "random string"; the
   specific thresholds are ours.
4. **The compute-attachment service list.** A curated false-positive control
   (§8), reasoned from how those services are used, not from an AWS list.
5. **The `system:serviceaccount:<namespace>:<serviceaccount>` IRSA subject
   shape.** Widely used and structurally handled, but not re-verified from
   primary documentation in this build.
6. **The structural segment-counting heuristic** for shared issuers without a
   bespoke grammar.

### Claims that were removed because they could not be verified

Both of these appeared in the project brief. Neither could be checked in the
environment this analyser was built in (only `docs.aws.amazon.com` was
reachable), so both were removed from all published material rather than
repeated:

1. **"Inadequate IAM is the top-ranked cloud threat in CSA's 2026 Top Threats
   report."** Not verified: the report was not retrievable, and neither its
   existence, its publication year, nor its ranking could be confirmed. No
   TrustEdge document cites a CSA ranking. If you want this claim in your
   write-up, check the current *Top Threats to Cloud Computing* report at
   <https://cloudsecurityalliance.org/> and cite the edition you actually read.
2. **"GitHub's 2026 immutable OIDC subject-claim changes."** Not verified: the
   GitHub changelog and docs were not retrievable. What *is* verified is AWS's
   own guidance that GitHub names are mutable and reclaimable and that
   `repository_id` / `repository_owner_id` / `actor_id` are immutable - that is
   what the analyser is built on and what the documentation cites. No claim
   about a dated GitHub change appears anywhere in this project. To check it,
   see <https://docs.github.com/en/actions/reference/workflows-and-actions/openid-connect>
   and the GitHub changelog.

No statistic, percentage, incident count or dated third-party claim appears
anywhere in TrustEdge's documentation or output. If you add one, add its source
here at the same time.

---

## 8. False-positive controls

A security tool that cries wolf gets muted. Four deliberate controls:

1. **Same-account trust is not inbound exposure.** Graded INTERNAL and omitted
   from the findings list unless `--include-internal` is passed - with the
   suppression disclosed in the report's limitations, so it is not a silent
   filter.
2. **Compute-attachment service principals are graded INTERNAL.** A trust
   policy naming `ec2.amazonaws.com` or `lambda.amazonaws.com` exists so *your
   own* workload can obtain credentials. Reporting "missing aws:SourceAccount"
   on every Lambda role in an account would bury the real findings. The
   controlling permission is `iam:PassRole` in your account, and the finding
   says exactly that. The list is a named table in `providers/aws.py`, not a
   heuristic, so it is reviewable and editable.
3. **Resource scope is honoured.** `iam:PassRole` on one named role is graded a
   tier below `iam:PassRole` on `*`, and the reasoning says which it was.
4. **Ungradable is not the same as bad.** An unclassifiable principal or a
   provider TrustEdge cannot reason about is graded NOT_DETERMINED, and severity
   is *capped at MEDIUM* for those - TrustEdge will not raise an alarm on the
   strength of a grade it could not determine.

---

## 9. Existing landscape and the honest gap

**Cloudsplaining** (Salesforce) assesses IAM *permission* policies for
over-privilege. It does not grade trust policies; the two documents answer
different questions.

**PMapper** (NCC Group) builds a graph of principals within an account and
computes privilege-escalation paths, including assume-role edges. It is
oriented towards *internal* escalation - "who inside can become who else" -
which is the question TrustEdge deliberately declines to answer (and says so
in every same-account finding).

**ScoutSuite, Prowler and Steampipe** are broad posture suites with some
trust-policy checks among hundreds of others. Their strength is coverage; the
weakness for this problem is that a trust-policy check sits in a flat list of
findings with no blast-radius pairing and no provider-aware condition grading.

**IAM Access Analyzer** is the closest AWS-native tool and is genuinely
stronger than TrustEdge at what it does. Verified from its documentation: it
"identifies resources shared with external principals by using logic-based
reasoning to analyze the resource-based policies in your AWS environment",
covers IAM roles among fifteen resource types, and works against a "zone of
trust". Two verified constraints are worth knowing: "For external access, IAM
Access Analyzer analyzes only policies applied to resources in the same AWS
Region where it's enabled", and it requires enablement in the account.

**What Access Analyzer does not give you**, and what TrustEdge is for: it tells
you a role is externally accessible; it does not grade *how strong* the
condition is on a provider-aware rubric, does not resolve the role's blast
radius, and does not rank the two together. TrustEdge also runs entirely
offline against an export, which matters for reviewing an account you do not
administer, an account you have not enabled the analyzer in, or a
Terraform-planned state.

**The honest gap statement.** This is not an unsolved security primitive. Every
signal TrustEdge uses is documented and most are available elsewhere. The value
is the combination: provider-aware condition-strength grading × blast-radius
resolution × offline execution × ranked, explainable findings. TrustEdge is a
complement to IAM Access Analyzer, not a replacement, and the tool says so in
its own output.

Sources:
<https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html>

---

## 10. Limitations

Summarised here in full in [limitations.md](limitations.md). The headline ones:

* TrustEdge reads a static export. It reports reachable trust paths, never
  proven exploitation.
* It does not evaluate SCPs, RCPs, permissions boundaries or session policies,
  any of which can make effective access narrower than reported.
* It cannot verify who controls an external account, an OIDC issuer or a SAML
  IdP. Vendor names come from an operator-supplied mapping and are labelled as
  such in every finding that uses them.
* It does not implement IAM authorisation. Blast radius is an approximation and
  every finding says which parts were approximated.
* Same-account escalation and full escalation-graph analysis are out of scope.

---

## 11. Sources

All fetched and read on 2026-09-07.

1. IAM and AWS STS condition context keys —
   <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html>
2. IAM JSON policy elements: Condition operators —
   <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html>
3. AWS global condition context keys —
   <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html>
4. The confused deputy problem —
   <https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html>
5. Access to AWS accounts owned by third parties —
   <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html>
6. Create a role for OpenID Connect federation (console) —
   <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html>
7. Identity-provider controls for shared OIDC providers —
   <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc_secure-by-default.html>
8. The IAM Roles Anywhere trust model —
   <https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html>
9. Cross-account policy evaluation logic —
   <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html>
10. Cross account resource access in IAM —
    <https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies-cross-account-resource-access.html>
11. Grant a user permissions to pass a role to an AWS service —
    <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html>
12. Using AWS IAM Access Analyzer —
    <https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html>
13. IAM roles for service accounts (Amazon EKS) —
    <https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html>

Not reachable during this build, and therefore not cited by any TrustEdge
document: cloudsecurityalliance.org, docs.github.com, docs.gitlab.com,
github.com.
