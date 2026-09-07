# Examples

| File | What it shows |
|---|---|
| [`library_usage.py`](library_usage.py) | Using TrustEdge as a library: analysing a file, grading a policy held in memory, asserting a property in your own test suite, filtering and rendering, and the error contract. |
| [`github-actions-gate.yml`](github-actions-gate.yml) | Wiring TrustEdge as a pull-request and scheduled gate on your own account's IAM export, including the read-only IAM permissions it needs and what *not* to upload as an artifact. |

## Run the library example

```bash
cd examples
PYTHONPATH=../src python library_usage.py
```

Or, once the package is installed (`pip install -e .` from the repository
root):

```bash
python examples/library_usage.py
```

## The shortest useful thing

Grading one trust policy, with no files involved:

```python
from trustedge import analyzer
from trustedge.parser import parse_export

export, issues = parse_export({
    "account_id": "111122223333",
    "roles": [{
        "role_name": "candidate",
        "arn": "arn:aws:iam::111122223333:role/candidate",
        "assume_role_policy_document": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::444455556666:root"},
                "Action": "sts:AssumeRole",
            }],
        },
    }],
})

finding = analyzer.analyze(export, issues=issues).findings[0]
print(finding.exposure.grade)            # WEAK
print(finding.exposure.who_can_assume)   # Any IAM principal in AWS account 444455556666
print(finding.score_explanation)          # exposure WEAK (0.75) x blast radius ...
```

## A note on asserting in your own tests

Assert on the **exposure grade**, not the severity number:

```python
assert finding.exposure.grade == ExposureGrade.STRONG
```

The grade is a statement about the trust policy and is stable. The severity is
a function of the grade *and* the role's permissions *and* the weight table, so
attaching your CI to it means an unrelated permission change can turn your
build red.

If you want a build gate on severity, use the CLI's `--fail-on`, which exists
for exactly that and distinguishes "found something" (exit 1) from "could not
run" (exit 2).
