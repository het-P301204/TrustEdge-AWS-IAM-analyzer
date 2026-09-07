# TrustEdge threat model

## The asset

Valid AWS credentials for a role inside the account under analysis, and
whatever those credentials reach.

## The attack surface

Every `Allow` statement in a role's `AssumeRolePolicyDocument` that names a
principal outside the account and permits `sts:AssumeRole`,
`sts:AssumeRoleWithWebIdentity` or `sts:AssumeRoleWithSAML`. One statement is
one door. A role can have several, guarded to different degrees.

## Attacker model

**Capabilities assumed.**

| Capability | Why it is reasonable |
|---|---|
| Knows or can guess role ARNs | Role ARNs are not secrets. AWS says of the closely-related external ID: "AWS does not treat the external ID as a secret… The external ID for a role can be seen by anyone with permission to view the role." Role names are also frequently in public IaC, blog posts and error messages. |
| Can obtain a token from any **shared** identity provider | By being an ordinary customer of it. Anyone can create a GitHub organisation and a workflow that requests an OIDC token from `token.actions.githubusercontent.com` — the same issuer URL your account trusts. |
| Controls their own tenancy within that provider | Can create repositories, branches, tags, environments, workspaces and service accounts, and can name them whatever they like. |
| Can register a GitHub organisation or repository name that has been freed | AWS: "A name that is freed by renaming or deletion can be claimed by a different account." |
| Has their own AWS account, with principals in it | Free to create. |
| Can read anything a read-only role permits | The starting point of most real escalation chains. |

**Capabilities *not* assumed.**

* No code execution in the target account.
* No compromise of an identity provider's signing keys.
* No compromise of a legitimately trusted vendor's systems.
* No ability to modify the target account's IAM configuration.
* No network position inside the target's VPCs.

## Attack paths TrustEdge is built to surface

### 1. Shared-issuer tenancy confusion

The role trusts `token.actions.githubusercontent.com` (or GitLab, Terraform
Cloud, Buildkite, Codefresh, Scalr, Vercel, Pulumi, …) with no effective
condition on the tenancy claim. The attacker creates their own org/repo on that
provider, runs a workflow that requests an OIDC token for `sts.amazonaws.com`,
and calls `AssumeRoleWithWebIdentity` with the victim's role ARN.

AWS's own warning: "If you do not limit the condition key
`token.actions.githubusercontent.com:sub` to a specific organization or
repository, then GitHub Actions from organizations or repositories outside of
your control are able to assume roles associated with the GitHub IAM IdP in
your AWS account."

AWS now blocks *creating* such a policy for recognised shared issuers, but
states plainly: "Identity-provider controls will not be evaluated by IAM for
existing OIDC role trust policies." Which is why auditing what is already
deployed is the point.

**Detected as:** `OPEN` on the `oidc.*` rubrics;
`shared_issuer_tenancy_claim_missing`, `github_sub_org_not_pinned`.

### 2. The condition that enforces nothing

The trust policy contains a condition on the right claim, with the wrong
operator. `StringEqualsIfExists` on `token.actions.githubusercontent.com:environment`
looks like a production gate. AWS documents that `environment` is only present
when the workflow declares one, and that `...IfExists` "evaluate[s] the
condition element as true" when the key is absent. A workflow that simply does
not declare an environment satisfies it.

`ForAllValues:` has the same failure mode: "returns true if there are no
context keys in the request".

**Detected as:** `if_exists_vacuous`, `forallvalues_vacuous`, with
`vacuous: true` on the weakness so it is machine-filterable.

### 3. Sibling-repository lateral movement

The subject condition pins the organisation but wildcards the repository
(`repo:acme-corp/*`), or pins the repository but not the ref
(`repo:acme-corp/infra:*`). Any repository in the org — including a
low-privilege one an intern can push to — or any branch in the repo, including
one the attacker creates, reaches production credentials.

**Detected as:** `WEAK` (org-only) or `MODERATE` (repo-only), with the reasoning
naming what is unpinned.

### 4. Renamed-organisation reclamation

The policy pins only name-based claims. The organisation is renamed or deleted;
the attacker registers the freed name; their workflows now satisfy the subject
condition. Mitigated by `repository_id`, `repository_owner_id`, `actor_id` or
`enterprise_id`, which AWS documents as immutable.

**Detected as:** `github_mutable_identifiers_only` (a hardening gap, reported
without changing the grade — see [methodology](methodology.md#51-oidc--ci-federation--oidc)).

### 5. Cross-account confused deputy

The role trusts a vendor's account with no `sts:ExternalId`. Another of that
vendor's customers supplies your role ARN to the vendor's console; the vendor
dutifully assumes it. This is AWS's own worked example of the confused deputy
problem, and the external ID is its documented mitigation — but only when the
value is generated by the vendor, unique per customer and not guessable.

**Detected as:** `WEAK` cross-account with `external_id_missing`, or
`external_id_weak_value` when the value is your own account id, the role name,
the vendor's name, short, all-digits or single-character-class.

### 6. Wildcard principal with a decorative guard

`Principal: "*"` guarded only by `sts:ExternalId`, or by `aws:SourceIp`. The
external ID is documented as non-secret and visible to anyone who can read the
role; an IP range restricts *how* the call is made, not *who* makes it. Neither
establishes identity, so the door is open to any AWS principal who learns the
value or arrives from the right network.

**Detected as:** `WEAK` with `wildcard_principal_external_id_only` or
`wildcard_principal_contextual_conditions_only`; `OPEN` when there is no
condition at all.

### 7. Certificate-authority substitution (Roles Anywhere)

The role pins `aws:PrincipalTag/x509Subject/CN` but not `aws:SourceArn`. A
common name is unique only *within* a CA. Adding a trust anchor anywhere in the
account — a legitimate operation, done for an unrelated project — silently
widens this role's trust to any certificate that new CA issues with the same
CN.

**Detected as:** `MODERATE` with `roles_anywhere_trust_anchor_not_pinned`.

### 8. Namespace-wide workload identity (IRSA)

The subject condition is `system:serviceaccount:*:*`, or absent. Any pod in the
cluster that can project a service-account token reaches the role. AWS's own
warning applies: "Containers are not a security boundary, and the use of IAM
roles for service accounts does not change this."

**Detected as:** `MODERATE` with `irsa_subject_not_pinned` / `irsa_subject_missing`
— deliberately *not* OPEN, because the cluster's issuer is private.

### 9. Federated-directory over-reach (SAML)

The trust policy contains only `saml:aud`. That pins the assertion's recipient
endpoint, not its subject, so as far as IAM is concerned every user the
corporate directory federates can take the role. This is often intentional,
with the IdP doing role assignment — but the trust policy is not enforcing it,
and that should be a decision rather than an accident.

**Detected as:** `MODERATE` with `saml_no_subject_condition`.

### 10. Escalation after entry

Any of the above, onto a role holding `iam:PassRole` plus a compute-creation
permission, or a policy-mutation permission, or `iam:UpdateAssumeRolePolicy` —
which lets the attacker rewrite the very trust policies this tool analyses and
make themselves permanently trusted.

**Detected as:** blast radius `HIGH` or `ADMIN`, with the specific primitive
named. This is the multiplier that turns a weak door into a critical finding.

---

## What TrustEdge deliberately does not model

| Out of scope | Why, and what does cover it |
|---|---|
| Intra-account privilege escalation | A different question with different tooling (escalation-graph tools model it properly). Every same-account finding says this. |
| Identity-provider compromise | Nothing in an IAM export speaks to it. |
| Compromise of a legitimately trusted vendor | TrustEdge cannot see the vendor's systems, and says so wherever a vendor name appears. |
| Whether a trust relationship is still *wanted* | A business question. `vendor_accounts` and `trusted_account_ids` in the export turn it into a reviewable inventory; TrustEdge will not guess. |
| Resource-based policies on other resources | S3 buckets, KMS keys, SQS queues etc. also grant external access. IAM Access Analyzer covers fifteen resource types; TrustEdge covers role trust policies specifically. |
| Whether a caller's own account permits the call | AWS requires an Allow in both the identity policy and the resource policy for cross-account access. TrustEdge sees one side, and every cross-account finding states it. |

## Consequences for how findings must be read

A TrustEdge finding is a statement about **reachability from the trust
policy's perspective**, ranked by what is behind it. It is never a statement
that an attack has occurred, that a path has been proven end to end, or that a
vendor has been compromised. The tool's output uses that language deliberately
and consistently:

* "Who can assume it" — the caller *set*, not a named attacker.
* "Reachable" and "candidate caller" — not "exploitable".
* "TrustEdge cannot verify…" — wherever external state would be required.
