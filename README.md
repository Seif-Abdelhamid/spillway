# Spillway

**Who can reach your S3 buckets and IAM roles after this Terraform change?**

Spillway reads `terraform show -json` output and works out, for every bucket and role, what
an *outsider* could do: anyone on the internet, or any principal in an AWS account you do not
own. It compares the plan's before and after states, so a pull request fails only on exposure
that the PR itself *adds*. Results come out as text, JSON or SARIF, which shows up as GitHub
code-scanning annotations on the `.tf` line.

```
$ spillway examples/public-share/plan.json
spillway 0.1.0: analyzed a Terraform plan

New in this change (6):
  NEW   CRITICAL SPW103  aws_iam_role.deploy
        GitHub OIDC trust accepts subject 'repo:*', which is not pinned to one owner's repository.
  NEW   HIGH     SPW203  aws_iam_role_policy.deploy
        PassAnything allows iam:PassRole on every role, a common privilege-escalation path.
  NEW   HIGH     SPW001  aws_s3_bucket_policy.shares
        Anyone on the internet (no AWS credentials) can read keys under shared/ in s3://acme-file-shares,
        via ShareLinksFromOurSite. aws:Referer is set by the requester, so it does not restrict access.
  ...
Gate: FAIL (4 finding(s) at or above the threshold)
```

## The problem

File sharing in the cloud often goes wrong through one small change. Someone needs share
links to work, turns off Block Public Access, and adds a bucket policy with
`"Principal": "*"`. They think the `aws:Referer` condition limits it to their own site, but
any client can set that header. Or a CI role trusts GitHub's OIDC provider with
`sub = repo:*`, so every GitHub repository in the world can assume it.

Pattern linters flag `"Principal": "*"` everywhere, and that is noisy, because
`"Principal": "*"` plus a `Deny` unless `aws:PrincipalOrgID` matches is a normal, safe
pattern. Spillway evaluates the policy the way AWS does instead (explicit deny, then allow,
then conditions), against an attacker model, and reports what is reachable:

* `Principal: *` limited to a VPC endpoint → **not reported** (the internet has no `aws:SourceVpce`)
* `Principal: *` with a Deny for anyone outside your org → **not reported**
* `Principal: *` with an `aws:Referer` or `aws:UserAgent` condition → **reported**, and the message says why
* A Deny that only covers plain HTTP → does not cancel the public grant
* A condition Spillway cannot decide (for example `s3:x-amz-acl`) → reported as *conditional*, one severity lower, never silently treated as safe

## Features

* **S3 effective exposure**: bucket policy, canned and explicit ACLs, bucket-level and account-level
  Block Public Access (`RestrictPublicBuckets` and `IgnorePublicAcls` neutralize grants),
  `BucketOwnerEnforced` (ACLs disabled). It reports read, write and admin (policy/ACL change)
  levels, including prefix-scoped grants ("keys under `shared/`").
* **IAM trust policies**: roles any AWS account can assume, cross-account trust without
  `sts:ExternalId`, and GitHub Actions OIDC trust not pinned to a repository.
* **Least privilege**: `Action: "*"` on `*`, whole-service wildcards, `iam:PassRole` on `*`,
  and `Allow` + `NotAction`.
* **Change-aware gate**: findings are labeled *new*, *already present* or *fixed*, using stable
  fingerprints. `--gate new` (the default) fails the build only on what the PR introduces.
* **SARIF 2.1.0** with `security-severity`, partial fingerprints, ATT&CK technique per rule, and
  `file:line` from `--tf-dir`, ready for `github/codeql-action/upload-sarif`.
* **Policies unknown until apply**: when a bucket is created in the same plan, its policy
  references `aws_s3_bucket.x.arn`, so the plan JSON holds no policy text at all. With
  `--tf-dir`, Spillway reads that policy from the `.tf` source (`jsonencode({...})`, heredoc or
  quoted JSON), fills in the bucket ARN from the bucket name the plan does know, and evaluates
  it. If any piece does not resolve at plan time, it stays SPW005 (fail closed).
* **Also scans applied state** (`terraform show -json` without a plan) for a posture check of
  what is deployed now.
* **Accept-in-code for public read**: a bucket tag `spillway:accept-public-read = "<reason>"`
  marks intended public *read* (such as a static site) as accepted. It never suppresses write or
  admin exposure, and a justification shorter than 10 characters is ignored.
* Standard library only: no runtime dependencies, no AWS credentials, no network calls.

### Rules

| ID | What | ATT&CK |
|---|---|---|
| SPW001 | Bucket policy grants outsiders read / write / admin | T1530 |
| SPW002 | ACL grants AllUsers / AuthenticatedUsers | T1530 |
| SPW003 | Bucket policy grants a named external account | T1530 |
| SPW004 | Service principal without `aws:SourceArn`/`aws:SourceAccount` (confused deputy) | T1530 |
| SPW005 | Policy could not be evaluated (computed at apply, malformed, unlinked): fails closed | - |
| SPW006 | Block Public Access explicitly turned off | T1530 |
| SPW101 | Role assumable by any AWS account | T1078.004 |
| SPW102 | Cross-account trust without `sts:ExternalId` / `aws:PrincipalOrgID` | T1078.004 |
| SPW103 | GitHub OIDC trust not pinned to a repository | T1078.004 |
| SPW201-204 | Admin wildcard, service wildcard, `iam:PassRole` on `*`, `Allow`+`NotAction` | T1098 |

## Security design and threat model

**What Spillway protects.** It protects the data in your buckets and the permissions behind
your roles, against outsiders who gain access through a misconfiguration that a Terraform change
introduces.

**The attacker model** (`spillway/conditions.py`). Each probe states, for every condition key,
what an attacker controls:

| Key kind | Examples | Anonymous | Any AWS account |
|---|---|---|---|
| absent | `aws:SourceVpce`, `aws:SourceArn`, `aws:PrincipalOrgID` (anonymous) | ✓ | |
| AWS-set, not yours | `aws:PrincipalAccount`, `aws:PrincipalOrgID`, `aws:PrincipalArn` | | ✓ |
| attacker-chosen | `aws:Referer`, `aws:UserAgent`, `sts:ExternalId` (when guessable) | ✓ | ✓ |
| fixed | `aws:SecureTransport = true` (the attacker just uses HTTPS), source IP outside your ranges | ✓ | ✓ |

Everything else is UNKNOWN. The engine uses three-valued logic (`tri.py`): an Allow that is
UNKNOWN is reported as conditional, and a Deny that is UNKNOWN is never relied on.

**Threats to Spillway itself.** In a PR pipeline, the plan is produced from code the PR author
controls, so Spillway treats it as untrusted input:

| Threat | Mitigation |
|---|---|
| Huge or deeply nested JSON to crash or hang the gate | 50 MB file cap; `RecursionError` caught; policy documents capped at 64 KB |
| Malformed policy that "parses as nothing" and so looks clean | Fail closed: SPW005 finding (medium), never "no exposure" |
| Policy computed at apply time hides a public grant | With `--tf-dir`, read from source when every reference resolves; otherwise fail closed with SPW005 |
| Hostile `.tf` source crafted to crash or hang the source reader | Hand-written parser for a small subset, nothing executed; file count, file size, nesting depth and policy size caps; any parse error falls back to SPW005; fuzzed with 3,000 mutated files |
| A Sid such as `"x\n::error::..."` or ANSI escapes injecting GitHub workflow commands or terminal escapes | Text output strips C0/C1 control characters and line separators (tested) |
| Suppressing a real finding | Suppression is a tag in reviewed Terraform code, needs a justification, covers public *read* only, and appears in SARIF as `inSource` suppression |
| Broken input mistaken for a pass | Distinct exit codes: 0 pass, 1 gate failed, 2 cannot analyze |
| Tool running with cloud credentials | No AWS SDK and no network. The example workflow uses a read-only plan role through OIDC pinned to the repo, and `pull_request` rather than `pull_request_target` |

**Known limits.** This is a static model, not the AWS policy engine. It does not evaluate
identity-side permissions of the attacker, SCPs or RCPs, KMS key policies, access points, or
`ForAnyValue`/`ForAllValues` operators, which are UNKNOWN. "Public" is approximated by the two
probes rather than AWS's exact definition. A bucket with no Block Public Access resource in the
plan is not assumed protected. AWS turns it on by default for new buckets, but the plan cannot
show account history. For a policy unknown until apply, the source reader handles only
root-module resources without `count`/`for_each`, and resolves only known plan values, bucket
and role ARNs (in the `aws` partition) and `data.aws_caller_identity` (from `--account-id`).
Variables, locals, function calls and template directives are not evaluated, so those policies
stay SPW005 instead of being guessed.

## Validated on a live AWS account

On 2026-11-22 Spillway was run against real `terraform plan` and `terraform show -json` output
from a personal AWS account:

* **Risky configuration, planned and never applied**: a bucket policy granting `s3:GetObject`
  to `*` behind an `aws:Referer` condition, Block Public Access partly off, and a GitHub OIDC
  role trusting `repo:*`. Before this release the bucket policy was SPW005 (unknown until
  apply). With `--tf-dir` the gate reports SPW103 (critical), SPW001 public read under
  `shared/` (high, Referer noted as requester-controlled) and SPW006.
* **Safe configuration, applied, scanned and destroyed**: a private bucket with all four Block
  Public Access settings, a TLS-only Deny policy, and a role trusting only its own account with
  an `sts:ExternalId`. Spillway reported no findings on the applied state.

## Architecture

```
terraform show -json ──► loader.py ──► Snapshot(before) ─┐
  (plan or state)        size/depth caps, resource_changes, │
                         after_unknown, config references   ├─► s3.py   bucket policy + ACL + BPA
                                                            ├─► iam.py  trust + identity policies
                         Snapshot(after) ───────────────────┘      │
                                                                   ▼
            policy.py (parse, wildcard match) ◄── evaluate.py (Deny > Allow, per probe/action)
                                                   conditions.py (attacker model, tri-state)
                                                                   │
                           analyze.py: fingerprints → new / existing / fixed, gate
                                                                   │
                           report.py: text (sanitized) · JSON · SARIF (+ locate.py file:line)
```

`source.py` runs before the analyzers when `--tf-dir` is given and fills in policies the plan
leaves unknown, marking them so findings say they were read from source.

Resource linking: a policy, ACL or Block Public Access resource is tied to its bucket by bucket
name. When the name is computed, Spillway uses the plan's `configuration` references
(`aws_s3_bucket.shares.id`), pairing `count`/`for_each` instances by index.

## Setup

Requires Python 3.11+.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .                    # no runtime dependencies
pip install -r requirements-dev.txt # tests, lint, scanners

pytest --cov=spillway               # 163 tests
ruff check . && ruff format --check .
bandit -c pyproject.toml -r spillway
```

### Use on your Terraform

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
spillway plan.json --account-id 111122223333            # text, fails on new high+
spillway plan.json --format sarif -o spillway.sarif --tf-dir .
spillway plan.json --gate all --fail-on medium          # stricter: everything currently present
terraform show -json > state.json && spillway state.json # posture of what is deployed
```

`docs/terraform-pr-gate.example.yml` is a ready GitHub Actions workflow: OIDC plan, Spillway,
SARIF upload.

### Demo

`examples/public-share/` holds a "share files by link" change (`main.tf`) and its plan
(`plan.json`). Run `python -m spillway examples/public-share/plan.json --tf-dir examples/public-share`.
Spillway reports the spoofable-Referer public read, the GitHub OIDC trust open to every
repository, `iam:PassRole` on `*`, and the Block Public Access flags turned off. It correctly
does **not** report the VPC-endpoint-only upload grant. CI asserts that this example exits with
code 1.

> Honesty note: `plan.json` was written by hand in Terraform's documented JSON plan format
> (`format_version` 1.2), because Terraform could not be installed in the sandbox where this
> project was built. It has not been run against a real AWS account. The test fixtures are
> built the same way.

## License

MIT, see [LICENSE](LICENSE).
