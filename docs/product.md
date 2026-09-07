# TrustEdge product definition

## The question

> **Who outside this AWS account can become an identity inside it, under what
> conditions, and what can they do once they are in?**

Everything in TrustEdge exists to answer that and to rank the answers so the
worst door is at the top.

## Who it is for

* A cloud security engineer reviewing an account they inherited, or auditing an
  account they do not administer.
* A platform team that wants a CI gate on trust-policy regressions without
  granting a scanner credentials.
* An incident responder who has an IAM export and no console access.

## What it is not

* Not a permission-policy over-privilege scanner. That is a different document
  and a different question.
* Not an intra-account privilege-escalation graph. TrustEdge grades doors that
  open from **outside**; every same-account finding says so and points at the
  tools built for that.
* Not a replacement for IAM Access Analyzer. See
  [research.md §9](research.md#9-existing-landscape-and-the-honest-gap).
* Not a GRC or compliance dashboard. There is no control mapping, no evidence
  workflow and no risk register here on purpose.

---

## Input

One JSON file. No credentials, no network, no agent, no analyzer enablement.

TrustEdge accepts two shapes and auto-detects which one it has been given:

1. **The native TrustEdge export**, documented below.
2. **The raw output of `aws iam get-account-authorization-details`**, converted
   in memory. `trustedge convert` writes the conversion out if you want it on
   disk.

### Native export schema

Every field except `roles` is optional, and the analyser degrades gracefully
and *visibly* when one is missing - a report built from a thin export says what
it could not determine.

```jsonc
{
  "trustedge_export_version": "1",

  // The account under analysis. Without it, TrustEdge cannot tell a
  // cross-account principal from a same-account one and grades every AWS
  // principal NOT_DETERMINED. Inferred from role ARNs when absent.
  "account_id": "111122223333",

  // Optional context. Purely operator assertions; see "Trust boundaries of
  // the input" below.
  "generated_at": "2026-09-07T00:00:00Z",
  "organization_id": "o-exampleorgid",
  "trusted_account_ids": ["222233334444"],

  // Operator-supplied vendor mapping. TrustEdge never verifies ownership and
  // says so in every finding that uses this.
  "vendor_accounts": {
    "444455556666": {
      "vendor": "Example Corp",
      "notes": "Cost optimisation SaaS; contract renewed 2026-01.",
      "requires_external_id": true
    }
  },

  // IAM identity providers. get-account-authorization-details does not return
  // these, so supply them with `trustedge convert --add`.
  "oidc_providers": [
    {
      "arn": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com",
      "url": "token.actions.githubusercontent.com",
      "client_id_list": ["sts.amazonaws.com"],
      "thumbprint_list": ["..."]
    }
  ],
  "saml_providers": [
    { "arn": "arn:aws:iam::111122223333:saml-provider/CorpDirectory",
      "name": "CorpDirectory" }
  ],

  // The policy library. Roles reference these by ARN; a role that attaches a
  // policy absent from this list gets blast radius UNKNOWN, not LOW.
  "managed_policies": [
    {
      "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
      "policy_name": "AdministratorAccess",
      "default_version_id": "v1",
      "policy_document": { "Version": "2012-10-17", "Statement": [ /* ... */ ] }
    }
  ],

  "roles": [
    {
      "role_name": "gh-deploy-payments-prod",
      "arn": "arn:aws:iam::111122223333:role/gh-deploy-payments-prod",
      "path": "/",
      "create_date": "2025-04-01T00:00:00Z",
      "description": "optional",
      "tags": { "owner": "payments" },

      // The object being analysed. Accepted as a JSON object, a JSON string,
      // or a URL-encoded JSON string (which is what get-role returns).
      "assume_role_policy_document": { "Version": "2012-10-17", "Statement": [ /* ... */ ] },

      "attached_managed_policies": [
        { "policy_name": "SyntheticDeployPipeline",
          "policy_arn": "arn:aws:iam::111122223333:policy/SyntheticDeployPipeline" }
      ],
      "inline_policies": [
        { "policy_name": "extra", "policy_document": { /* ... */ } }
      ],
      "permissions_boundary_arn": "arn:aws:iam::111122223333:policy/DevBoundary"
    }
  ]
}
```

Accepted shape variations, because real exports vary:

* Keys may be `snake_case` or AWS `PascalCase` (`role_name` or `RoleName`).
* `inline_policies` may be a list of `{policy_name, policy_document}` or a
  `{name: document}` map.
* `attached_managed_policies` entries may be objects or bare ARN strings.
* `Statement` may be a single object or a list.
* `Action`, `Resource` and condition values may be a string or a list.
* Unknown keys are ignored, so `_note` / `_scenario` annotations are safe.

### How to produce an export

Read-only, and you run it - TrustEdge never calls AWS:

```bash
aws iam get-account-authorization-details --filter Role > auth-details.json
aws iam list-open-id-connect-providers > oidc.json     # then get-... per ARN
aws iam list-saml-providers > saml.json

trustedge convert \
  --input auth-details.json \
  --add context-supplement.json \
  --output export.json
```

### Trust boundaries of the input

An IAM authorisation export is **sensitive**: it is a complete map of who can
do what in an account. Treat it like a credential inventory.

* TrustEdge never transmits it anywhere. There is no telemetry and no network
  code in the analyser at all.
* `trustedge serve` parses it in memory, binds to loopback by default, and
  writes nothing to disk.
* `vendor_accounts`, `trusted_account_ids` and `organization_id` are
  **assertions by whoever wrote the export**. TrustEdge repeats them and
  labels them as unverified. They can only make a finding *less* alarming, so a
  wrong assertion causes a false negative rather than a false positive - which
  is why every finding that uses one says so.

---

## Output

### Machine-readable JSON

`schema: "trustedge.report/1"`. Stable field names; new fields may be added
within the same schema version, existing ones are not renamed or removed.

```jsonc
{
  "schema": "trustedge.report/1",
  "tool": "TrustEdge", "tool_version": "0.1.0",
  "generated_at": "...", "input_path": "...", "account_id": "111122223333",
  "summary": {
    "roles_analyzed": 24, "trust_statements_analyzed": 26,
    "principals_analyzed": 26, "findings_total": 24,
    "severity_counts": { "CRITICAL": 3, "HIGH": 5, "...": 0 },
    "highest_severity": "CRITICAL"
  },
  "findings": [ /* see below */ ],
  "roles":  [ /* per-role inventory with blast radius and worst finding */ ],
  "input_issues": [ /* every field TrustEdge could not read */ ],
  "limitations": [ /* what this run cannot establish */ ]
}
```

### Every finding carries

| Field | What it is |
|---|---|
| `finding_id` | Stable across runs on the same input; independent of rank order |
| `title` | One line naming the role, the principal and the blast radius |
| `role_name`, `role_arn` | The role the door is on |
| `statement_index`, `statement_sid` | Which trust statement, so multi-door roles stay separable |
| `principal` | The verbatim Principal value, plus `block_key`, `account_id`, `provider_id`, `label` and notes |
| `principal_classification` | `same_account`, `cross_account`, `wildcard`, `aws_service`, `roles_anywhere`, `oidc`, `saml`, `canonical_user`, `unknown` |
| `provider` | `github_actions`, `eks_irsa`, `gitlab`, `terraform_cloud`, `shared_oidc`, `private_oidc`, `saml`, `roles_anywhere`, `aws_service`, `aws_account`, `any_aws_principal`, `unknown` |
| `exposure.grade` | `OPEN`, `WEAK`, `MODERATE`, `STRONG`, `INTERNAL`, `NOT_DETERMINED`, `NOT_APPLICABLE` |
| `exposure.who_can_assume` | One sentence naming the caller set |
| `exposure.reasoning` | Ordered prose reasons for the grade |
| `exposure.weak_conditions` | Named weaknesses, each with the condition key, the operator, whether it *neutralises* the guard, and a cited explanation |
| `exposure.fail_closed_notes` | Defects that make the statement unmatchable rather than permissive |
| `exposure.rubric` | Which rubric produced the grade, e.g. `oidc.github_actions` |
| `exposure.confidence` | `high`, `medium`, `low` |
| `exposure.limitations` | What this grade does not establish |
| `exposure.references` | AWS documentation URLs behind the rubric |
| `blast_radius.tier` | `ADMIN`, `HIGH`, `MODERATE`, `LOW`, `UNKNOWN` |
| `blast_radius.capabilities` | Each tagged `admin` / `escalation` / `data_plane`, with the action pattern, resource patterns and source policy |
| `blast_radius.unresolved_policies` | Attached policies whose documents were absent, so you know the tier is a lower bound |
| `risk_score` | 0-100, `exposure × blast radius` |
| `score_explanation` | The arithmetic in one checkable sentence |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `recommendation.summary` | What to change |
| `recommendation.tightened_trust_policy` | A concrete policy, **only when one can be produced without inventing values** |
| `evidence` | The verbatim trust statement, the parsed conditions, and the condition keys seen |

### Human-readable report

Markdown (default) or a self-contained HTML file. Both contain:

* **Executive summary** — roles, trust statements, principals graded, findings,
  severity counts, exposure-grade distribution, blast-radius distribution per
  role, and a highest-risk table.
* **Findings**, worst first — for each: who can assume it, why TrustEdge graded
  it that way, the weak conditions in a table, the verbatim trust statement,
  the blast radius with its capability table, the score arithmetic, the fix,
  what the finding does *not* establish, and the references.
* **Role inventory** — every role, its trust statements, principal classes,
  blast radius and worst finding.
* **Input issues** — every field that could not be read, so a thin export is
  visible rather than silently producing a clean report.
* **Limitations** — read before treating an empty findings list as an
  all-clear.

---

## Behavioural guarantees

These are contracts, and there are tests for each of them.

1. **Trust is never conflated with permissions.** Exposure grading reads only
   the `Principal` and `Condition` elements. Given the same trust statement, an
   admin role and a read-only role get the *same exposure grade* and different
   ranks.
2. **A malformed part never loses the whole.** One unreadable statement in a
   400-role export produces an issue and 399 analysed roles. The only hard
   failure is an input that is not an IAM export at all.
3. **Not detected ≠ not applicable ≠ not determined.** A statement that grants
   no assume-role action is `NOT_APPLICABLE`. A principal TrustEdge cannot
   classify is `NOT_DETERMINED` with severity capped at MEDIUM. A missing
   condition is a named weakness with a citation.
4. **Every grade is explainable and every score is checkable by hand.**
5. **Nothing is claimed that the export cannot support.** No "exploitable", no
   "compromised", no vendor-ownership assertions, no IAM-equivalence claims.
6. **Suppression is disclosed.** INTERNAL findings are omitted by default and
   the report says how many and how to see them.

---

## Non-goals for this version

Named here so scope creep is visible rather than accidental:

* Multi-account trust graphs (planned; see the README roadmap).
* Live AWS collection, exploitation, credential acquisition, or any offensive
  automation. Deliberately excluded, permanently.
* SCP, RCP, permissions-boundary or session-policy evaluation.
* Terraform/CloudFormation source analysis.
* A findings database, ticketing integration or trend history.
