<h1 align="center">TrustEdge</h1>

<p align="center">
  <strong>AWS inbound trust boundary analyzer.</strong><br>
  Who outside this account can become an identity inside it, how strong is the
  guard on that door, and what do they get once through?
</p>

<p align="center">
  <a href="https://github.com/het-P301204/TrustEdge-AWS-IAM-analyzer/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/het-P301204/TrustEdge-AWS-IAM-analyzer/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Python 3.9+" src="https://img.shields.io/badge/python-3.9--3.14-blue">
  <img alt="tests" src="https://img.shields.io/badge/tests-601_passing-brightgreen">
  <img alt="dependencies" src="https://img.shields.io/badge/runtime_deps-0-brightgreen">
  <a href="LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-blue"></a>
</p>

<p align="center">
  Findings are ranked by <strong>exposure × blast radius</strong> — so a weak
  door onto a powerful role outranks both a strong door onto a powerful role
  and a wide-open door onto a harmless one.
</p>

<p align="center">
  <em>No credentials. No API calls. No agent. Runs offline from an IAM export.</em>
</p>

---

## The two things it catches

**1. A condition that looks like a guard and enforces nothing.**

```json
"Condition": {
  "StringLike":           { "token.actions.githubusercontent.com:sub": "repo:acme/deploy:*" },
  "StringEqualsIfExists": { "token.actions.githubusercontent.com:environment": "production" }
}
```

That reads like a production gate. It isn't. AWS documents that `...IfExists`
evaluates to **true** when the key is absent, and that GitHub only issues the
`environment` claim when the workflow declares one. A workflow that omits
`environment:` satisfies it by omission.

→ `if_exists_vacuous`, and the condition is not credited as a guard.

**2. The same omission meaning different things on different providers.**

AWS splits OIDC providers into **shared** (issuer URL identical for every
customer) and **private** (unique to one org). A missing `sub` condition on
`token.actions.githubusercontent.com` lets a stranger's workflow in — every
GitHub customer mints tokens from that same URL. The same omission on an EKS
cluster's own issuer bounds the caller to that cluster.

→ `OPEN` for the first, `MODERATE` for the second. A tool that calls both
"condition missing" is a tool people mute.

> **Why offline still matters:** AWS now rejects *new* GitHub OIDC trust
> policies without a `sub` condition — but states plainly that
> *"identity-provider controls will not be evaluated by IAM for existing OIDC
> role trust policies."* The ones already deployed are grandfathered.

---

## Quickstart

```bash
pip install -e .

trustedge analyze --input fixtures/sample-account.json          # report to stdout
trustedge analyze -i export.json -o report.html                 # format from extension
trustedge analyze -i export.json --fail-on high                 # CI gate
trustedge validate -i export.json                               # what couldn't be read
trustedge serve                                                 # local viewer, loopback
```

From your own account — read-only, and **you** run it:

```bash
aws iam get-account-authorization-details --filter Role > auth.json
trustedge convert -i auth.json --add context.json -o export.json
trustedge analyze -i export.json -o report.md
```

**Exit codes:** `0` clean · `1` findings at `--fail-on` · `2` bad input · `3` bug.
The 1/2 split matters — a pipeline that conflates them goes green when someone
mistypes a path.

---

## Example

```console
$ trustedge analyze -i fixtures/sample-account.json -o report.json -f json
TrustEdge 0.1.0: 24 role(s), 26 trust statement(s), 24 finding(s)
(3 critical, 5 high, 11 medium, 4 low, 1 info) -> report.json
```

Three findings from that run, showing why the model is a product and not a sum:

| Role | Exposure | Blast radius | Risk | |
|---|---|---|---:|---|
| `partner-broad-access` — whole external account, no external ID | `WEAK` | `ADMIN` | **75** | 🔴 CRITICAL |
| `partner-admin-pinned` — one role ARN + strong external ID | `STRONG` | `ADMIN` | 15 | 🟡 MEDIUM |
| `public-status-reader` — `Principal: "*"`, no conditions | `OPEN` | `LOW` | 15 | 🟡 MEDIUM |

A locked-down admin role is a design smell. A wide-open role that can only call
`sts:GetCallerIdentity` is a hygiene item. Row one is the one worth waking up
for.

Every finding carries the verbatim trust statement, the named weak conditions,
the resolved capabilities, a one-sentence score you can check by hand
(`exposure OPEN (1.00) x blast radius ADMIN (1.00) = 100`), a fix, and what the
finding does *not* establish.

---

## What it grades

| Principal | Graded on |
|---|---|
| **GitHub Actions OIDC** | Subject grammar, plus AWS's documented `repository`, `repository_id`, `repository_owner_id`, `job_workflow_ref`, `ref`, `environment`, `actor_id`, `enterprise_id` claims; mutable vs immutable identifiers |
| **EKS IRSA** | Namespace and service-account specificity, with a private-issuer floor |
| **Shared OIDC issuers** | The tenancy claim AWS documents per issuer — GitLab, HCP Terraform, Buildkite, Codefresh, Scalr, Vercel, Pulumi, Cognito, Upbound, and more |
| **Private OIDC issuers** | Subject specificity, with an explicit caveat if it's really multi-tenant |
| **SAML 2.0** | `saml:aud` vs subject vs group attributes; `saml:sub_type` |
| **IAM Roles Anywhere** | Trust anchor × certificate identity — a CN is only unique *within* a CA |
| **Cross-account** | Root vs named principal, `sts:ExternalId` quality, `aws:PrincipalArn`, `aws:PrincipalOrgID` |
| **Wildcard `*`** | Whether any condition bounds *identity* rather than context |
| **AWS service** | Confused-deputy source conditions, with a compute-attachment carve-out |

Blast radius resolves admin-equivalence, ~30 escalation primitives
(`iam:PassRole`, `iam:CreatePolicyVersion`, `iam:UpdateAssumeRolePolicy`,
`sts:AssumeRole` chains…), data-plane reach, and combinations —
`iam:PassRole` alone is MODERATE; paired with a compute-creation action it's
HIGH, because passing a role only becomes code execution when something runs
code.

---

## Ranking

```
risk = round(100 × exposure_weight × blast_weight)
```

| Exposure | | Blast radius | |
|---|---:|---|---:|
| `OPEN` | 1.00 | `ADMIN` | 1.00 |
| `WEAK` | 0.75 | `HIGH` | 0.75 |
| `MODERATE` | 0.45 | `MODERATE` | 0.45 |
| `STRONG` | 0.15 | `LOW` | 0.15 |
| `INTERNAL` | 0.05 | `UNKNOWN` | 0.40 |
| `NOT_DETERMINED` | 0.40 | | |

≥60 CRITICAL · ≥35 HIGH · ≥15 MEDIUM · ≥5 LOW. Severity is **capped at MEDIUM**
when exposure is `NOT_DETERMINED` — no alarms on the strength of a grade the
tool couldn't determine.

Full rubrics, the complete risk matrix and the reasoning behind every weight:
**[docs/methodology.md](docs/methodology.md)**.

---

## Limitations

* **Reachability, not exploitability.** It reports what a trust policy admits.
  It never executes anything.
* **Cross-account needs both sides.** AWS requires an Allow in the identity
  policy *and* the resource policy. TrustEdge sees one side.
* **Blast radius is an approximation, not IAM authorisation.** Permissions
  boundaries, SCPs, RCPs and session policies are not evaluated.
* **No external state is verified** — not account ownership, not who runs an
  OIDC issuer, not whether a vendor relationship is current.
* **Not a replacement for IAM Access Analyzer.** Different tool, different
  question. Run both.

Every limitation is emitted on the finding it applies to, not buried in a
footer. Full list: **[docs/limitations.md](docs/limitations.md)**.

Two claims from the original project brief were **removed** because they
couldn't be verified from primary sources — a CSA threat ranking and a dated
GitHub OIDC change. Neither appears anywhere in this project, and CI fails the
build on an unsourced statistic in the docs.

---

## Docs

| | |
|---|---|
| [research.md](docs/research.md) | Every rule traced to primary AWS documentation, with quotations — plus **verified / inferred / removed** tables |
| [methodology.md](docs/methodology.md) | Rubrics, weights, risk matrix, how to change a rule |
| [threat-model.md](docs/threat-model.md) | Attacker model and the ten attack paths behind the rubrics |
| [architecture.md](docs/architecture.md) | Data flow, module boundaries, design decisions |
| [product.md](docs/product.md) | Export schema, finding schema, behavioural guarantees |
| [limitations.md](docs/limitations.md) | What it can't determine, and known false positives/negatives |

---

## Development

```bash
pip install -e ".[dev]"
pytest                     # 601 tests
```

Standard library only — no runtime dependencies, so it runs air-gapped. CI runs
the suite on Python 3.9–3.13, byte-compiles every module, exercises the CLI end
to end, and scans the repo for anything credential-shaped.

```bash
docker build -t trustedge .
docker run --rm --network none -v "$PWD:/work" -w /work trustedge \
  analyze -i fixtures/sample-account.json -o reports/report.md
```

**Security notes:** an IAM authorisation export is a complete map of who can do
what — treat it like a credential inventory. The analyser has no network code
at all. `trustedge serve` binds loopback, holds no state, and writes nothing to
disk. Every fixture in this repo is synthetic; the account IDs are AWS's
documentation examples.

---

## Roadmap

Multi-account trust graphs · `iam:PassRole` target resolution ·
permissions-boundary intersection · a verified GitLab subject parser ·
Terraform plan input · findings emitted in a shape
[AegisLens](https://github.com/het-P301204/AegisLens-security-workbench) can
ingest.

---

MIT © [Het Patel](https://github.com/het-P301204)
