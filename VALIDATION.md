# Validation Report — V's AWS Hardening Kit

> This is the validation report for **V's AWS Hardening Kit**, published in full and outside the
> paywall. It records what was actually executed against live AWS, including every defect the
> exercise found in the kit's own code. The free read-only audit script in this repository is the
> extracted, give-away part of the same toolkit.

**Date:** 2026-09-08 (updated same day with the ASG-clone round)
**Covers:** the kit at **v0.4.0**. See *Scope of this report* below for what changed since.
**Region:** us-east-1
**Method:** Isolated sandbox VPC (`10.42.0.0/16`), purpose-built for this validation and
destroyed afterwards. No pre-existing infrastructure was modified.

This document records what was actually executed, not what was intended. Every command in the
how-to guides (`docs/how-to/`, one per component) was run against live AWS before publication.

---

## Summary

| Gate | Result |
|---|---|
| YAML parse (23 files) | **PASS** |
| `cfn-lint` schema validation (14 templates) | **PASS** — no findings |
| `aws cloudformation validate-template` (14 templates) | **PASS** — all 14 |
| ShellCheck (7 scripts) | **PASS** — clean |
| `actionlint` (9 workflows) | **PASS** — clean |
| Live stack deployment (9 stacks) | **PASS** |
| ALB functional checks (7) | **PASS** — all 7 |
| Guardrail AUDIT mode | **PASS** — detection in 3s |
| Guardrail REMEDIATE mode | **PASS** — auto-revoked in 6s |
| Existing-ALB retrofit | **FAILED, defect fixed, re-verified PASS** |
| ASG stack clone | **FAILED, two defects fixed, re-verified PASS** |
| Terraform: fmt / validate / tflint (16 configs) | **PASS** |
| Terraform: checkov | **PASS** — 268 passed, remaining findings suppressed with written justifications |
| Terraform: live apply / functional / idempotency / destroy | **FAILED twice, defects fixed, re-verified PASS** |

**Eleven defects were found and fixed.** Six would have caused a failure on first use; one
would have caused a production outage.

---

## Scope of this report

This report covers the live validation round of **2026-09-08**, which is the kit at **v0.4.0**.
The kit is now at **v0.12.0**, and those eight releases are **not** covered by a re-run of the
full live round. They are recorded, change by change, in `CHANGELOG.md`, and the significant
ones were driven by outside review rather than by me:

| Since v0.4.0 | What changed |
|---|---|
| 0.5.0 | Mutating scripts verify from outside after applying, and self-heal — exit codes come from probing the invariant, not from AWS calls returning 200 |
| 0.6.0 | Three explicit phases: discover, plan, apply. The plan describes end state, not calls |
| 0.7.0 | A false CRITICAL on private-CIDR SSH; a failed AWS query that read as "nothing found" |
| 0.8.0 | Adversarial pass: three of four Terraform assertions were checking their own inputs; `ssl_policy` validation was tautological |
| 0.9.0 – 0.11.0 | AMI lifecycle — launch templates pinned to deregistered AMIs, repair, and an instance-refresh precondition that had never worked |
| 0.12.0 | **Exit code 7, "applied, but nothing was proven"** — `--force` over a missing target group now exits 7 instead of 0 |

Three of those defects came from r/devops taking the first version apart, and each one shipped
as a release before I replied. Nine more came from a later pass where I stopped testing whether the tools
worked and started trying to make them lie — two of those were inside fixes shipped the same
morning.

⚠️ **So read the table below as the v0.4.0 evidence, not as a claim about v0.12.0.** The next
live round is what re-dates this document, and it has not been run yet.

---

## Defects found and fixed

### 1. Auto Scaling group failed using its own default value — *critical*

`cloudformation/compute/autoscaling-group.yaml` defaulted `LaunchTemplateVersion` to
`'$Default'`. CloudFormation rejects both `$Default` and `$Latest` for
`AWS::AutoScaling::AutoScalingGroup`:

```
Resource handler returned message: "CloudFormation does not support using $Latest
or $Default for LaunchTemplate version. Please specify a version number or name."
```

The stack could not deploy with stock parameters. **Fixed:** default changed to `'1'` with a
description directing users to the launch-template stack's `LatestVersionNumber` output.
Re-deployed successfully; ASG created with `HealthCheckType: ELB`.

### 2. Existing-ALB retrofit took the application offline — *critical*

`scripts/remediate/harden-existing-alb.sh` discovered the forward target group **only** from
the HTTPS/443 listener. Against an HTTP-only legacy ALB — a very common starting state — it:

- rewrote port 80 from `forward` to `redirect`
- created an HTTPS listener with a 403 default action
- never carried the target group across

Measured result against a legitimate request on an **allowed** hostname:

```
HTTPS, allowed host  → 403 "Host not allowed"
Target group LoadBalancerArns → []      (orphaned)
```

The application was completely unreachable. The script printed
`ALB hardening complete.` and exited **0**.

**Fixed:** the target group is now read from HTTP/80 as a fallback, captured *before* any
listener is modified; the host-allow rule is created *before* the default becomes 403; and the
script **aborts without changing routing** when no target group can be found. Added `--dry-run`
and `--force`.

Re-verified after the fix:

| Request | Before fix | After fix |
|---|---|---|
| HTTP, allowed host | 301 | 301 |
| HTTPS, allowed host | **403 (outage)** | **503 — forwarded to preserved TG** |
| HTTPS, unknown host | 403 | 403 |
| Target group attachment | **orphaned** | **re-attached** |

### 3. A CloudFormation-created ASG could not be cloned at all — *critical*

`scripts/asg/clone-asg-stack.sh` copied the source ASG's tags verbatim. CloudFormation stamps
`aws:cloudformation:logical-id`, `:stack-id` and `:stack-name` onto every resource it creates,
and AWS forbids setting tags in the reserved `aws:` namespace on a new resource:

```
An error occurred (ValidationError) when calling the CreateAutoScalingGroup operation:
Your account is not allowed to create tag aws:cloudformation:logical-id
```

This meant an ASG created by **this toolkit's own `autoscaling-group.yaml`** could never be
cloned — a guaranteed failure for the toolkit's own users. **Fixed:** `aws:`-prefixed tags are
filtered out of both the ASG and the target-group tag copies. Re-verified: the clone now carries
`Environment` and `ManagedBy` plus a replaced `Name`, and none of the reserved tags.

### 4. A failed clone left orphans that blocked its own retry — *high*

The clone creates target groups and a launch template *before* the ASG. When the ASG creation
failed above, those partial resources remained. The script's own pre-flight checks then refuse
to run while a destination target group or launch template already exists — so a failed run
blocked its own retry until the operator manually hunted down and deleted the leftovers.

**Fixed:** the script now tracks what it creates and removes it on failure via an `EXIT` trap,
reporting each removal and confirming the source was untouched. `CLONE_ROLLBACK_ON_FAILURE=false`
opts out and instead prints exactly what was left behind.

Verified by forcing a failure after both target groups were created:

```
Clone failed. Rolling back partial resources...
  removed target group .../tg-vsdt-api-qa5/0874e02a6564410e
  removed target group .../tg-vsdt-web-qa5/a3130133cd077b00
Rollback complete. The source environment was not modified.
```

A retry with corrected arguments then succeeded immediately, which was the point of the fix.

### 5. Scripts broke on any non-JSON AWS CLI profile — *high*

Four scripts pipe AWS CLI output into `jq` but did not force JSON. On a profile configured with
`output = yaml` (a documented AWS CLI option), the audit script died mid-run:

```
jq: parse error: Invalid numeric literal at line 1, column 7
```

**Fixed:** `export AWS_DEFAULT_OUTPUT=json` added to all four scripts. The audit script now
completes and correctly reports WAF association.

### 6. Remediation script required bash 4 — *medium*

`scripts/remediate/restrict-admin-ingress.sh` used `mapfile`, a bash 4+ builtin. macOS ships
bash 3.2, where it fails with `mapfile: command not found`.

**Fixed:** replaced with a portable `while read` loop. Verified working under
`/bin/bash` 3.2.57 on macOS, including the idempotent second run.

### 7. Unused parameter advertised a control that did not exist — *low*

`cloudformation-execution-role.yaml` exposed an `AllowedVpcId` parameter described as a "VPC
guardrail". It was referenced nowhere and enforced nothing. Flagged by `cfn-lint` as W2001.

**Fixed:** parameter removed. `cfn-lint` is now clean across all templates.

### 8. Deploy workflow parameter handling was fragile — *low*

`deploy-cloudformation.yml` used `${PARAMS:+--parameter-overrides "${PARAMS[@]}"}`, which
word-splits and breaks on parameter values containing spaces.

**Fixed:** rebuilt as a guarded argument array. Inputs are now passed via `env:` rather than
interpolated into the script body, removing a script-injection vector. `actionlint` clean.

---

## Live deployment results

Nine stacks deployed successfully into the sandbox VPC:

| Stack | Template | Result |
|---|---|---|
| `vsdt-sb-ssm-role` | `iam/ssm-ec2-role.yaml` | CREATE_COMPLETE |
| `vsdt-sb-sgs` | `networking/no-ssh-security-groups.yaml` | CREATE_COMPLETE |
| `vsdt-sb-logs` | `alb/alb-access-logs-bucket.yaml` | CREATE_COMPLETE |
| `vsdt-sb-alb` | `alb/hardened-alb.yaml` | CREATE_COMPLETE (access logs enabled) |
| `vsdt-sb-waf` | `waf/alb-webacl.yaml` | CREATE_COMPLETE (associated) |
| `vsdt-sb-alarms` | `observability/alb-waf-alarms.yaml` | CREATE_COMPLETE |
| `vsdt-sb-cfnrole` | `iam/cloudformation-execution-role.yaml` | CREATE_COMPLETE |
| `vsdt-sb-winlt` | `compute/hardened-windows-launch-template.yaml` | CREATE_COMPLETE |
| `vsdt-sb-remediator` | `guardrails/event-driven-remediator.yaml` | CREATE_COMPLETE |
| `vsdt-sb-asg` | `compute/autoscaling-group.yaml` | CREATE_COMPLETE *(after fix 1)* |

Not deployed, for documented environmental reasons:

- **`bootstrap/github-oidc-provider.yaml`** — the test account already had an OIDC provider for
  `token.actions.githubusercontent.com`. AWS permits only one per URL per account. Template
  validated; documented in guide 01, *GitHub OIDC provider*.
- **`config/security-config-rules.yaml`** — the account had no AWS Config recorder
  (`describe-configuration-recorders` returned empty), which the stack requires. Template
  validated; documented in guide 13, *Security Config rules*.
- **`waf/api-gateway-webacl.yaml`** — no REST API stage existed to associate with. Template
  validated.
*(`scripts/asg/clone-asg-stack.sh` was previously untested for the same reason. It has since been
validated end to end — see the next section.)*

## ALB functional checks

All seven checks from the sandbox test plan passed against the live ALB:

| # | Check | Expected | Actual |
|---|---|---|---|
| 1 | HTTP/80 redirect | 301 | **301 Moved Permanently** |
| 2 | HTTPS, allowed host | forwarded | **503** — rule matched, no targets registered |
| 3 | HTTPS, unexpected host | 403 | **403 "Host not allowed"** |
| 4 | `drop_invalid_header_fields` | true | **true** |
| 4 | `desync_mitigation_mode` | defensive | **defensive** |
| 4 | `access_logs.s3.enabled` | true | **true** |
| 5 | TLS policy | TLS13-1-2-2021-06 | **ELBSecurityPolicy-TLS13-1-2-2021-06** |
| 6 | WAF association | present | **vsdt-sb-alb-webacl** |
| 7 | SSH/RDP ingress | none | **none** |

Check 7 also confirmed the ALB security group's egress is restricted to the application group
on port 8080 only — the template's empty `SecurityGroupEgress: []` correctly suppresses the
default allow-all rule.

Check 6 additionally validated the S3 bucket policy: AWS verifies log delivery when access
logging is enabled and rejects the load balancer otherwise. The ALB created cleanly, which
proves the `logdelivery.elasticloadbalancing.amazonaws.com` service principal is correct for
this region.

## Guardrail checks

**AUDIT mode.** A public SSH rule (`0.0.0.0/0:22`) was added to a throwaway security group.
The Lambda logged a finding **3 seconds** later:

```json
{"kind": "sg-admin", "resource": "sg-0c33…", "status": "NONCOMPLIANT",
 "detail": {"rule": "sgr-0bef…", "cidr": "0.0.0.0/0", "ports": [22, 22]}, "mode": "AUDIT"}
```

**REMEDIATE mode.** The stack was switched to `REMEDIATE` and a public RDP rule
(`0.0.0.0/0:3389`) added. Within **6 seconds** the Lambda revoked both the new RDP rule *and*
the pre-existing SSH rule, leaving the group with zero ingress rules. Verified by
`describe-security-group-rules` returning empty.

This confirms a documented behaviour worth restating: the remediator re-evaluates the **entire
security group**, not only the rule in the triggering event.

## ASG stack clone

A dedicated source environment was built in a second sandbox VPC (`10.43.0.0/16`) specifically
to exercise `clone-asg-stack.sh`, which had never been run. It was built from the toolkit's own
templates so the test would reflect real usage:

- `no-ssh-security-groups.yaml` → application security group
- `ssm-ec2-role.yaml` → instance profile
- `hardened-windows-launch-template.yaml` → launch template `lt-vsdt-demo-qa`
- two target groups with deliberately distinct settings — `tg-vsdt-web-qa` (port 8080,
  `/healthz`, 15s interval, 10s timeout, thresholds 3/4, matcher 200-299, 45s deregistration
  delay, `lb_cookie` stickiness) and `tg-vsdt-api-qa` (port 9090, `/api/health`, matcher
  200-399, 120s deregistration delay)
- `autoscaling-group.yaml` → ASG `asg-vsdt-demo-qa`, both target groups attached, `AZRebalance`
  suspended

The first run **failed** — defect 3 above. After the fix, the clone (`qa` → `qa3`) succeeded and
was compared field by field against the source:

| Property | Source | Clone | Match |
|---|---|---|---|
| Target-group protocol, port, VPC, target type | — | — | ✅ both TGs |
| Health-check path, interval, timeout, thresholds, matcher | — | — | ✅ both TGs |
| Deregistration delay / stickiness attributes | 45s / `lb_cookie` | 45s / `lb_cookie` | ✅ |
| Target-group tags | `Tier`, `ManagedBy`, `Name` | same, `Name` replaced | ✅ |
| Launch template AMI, type, IMDSv2, hop limit, encryption, volume size, instance profile | — | — | ✅ identical |
| Launch template instance `Name` tag | `lt-vsdt-demo-qa` | `vsdt-demo-qa3` | ✅ replaced |
| ASG health-check type / grace / cooldown | ELB / 300 / 300 | ELB / 300 / 300 | ✅ |
| Availability zones, termination policies | 2 AZs / Default | 2 AZs / Default | ✅ |
| Suspended processes | `AZRebalance` | `AZRebalance` | ✅ carried over |
| Attached target groups | 2 | 2 | ✅ |
| ASG tags | includes 3 `aws:cloudformation:*` | reserved tags stripped | ✅ correct |
| Capacity | Min 0 / Max 4 | **Min 0 / Max 0 / Desired 0** | ✅ intentional |

The clone is deliberately created at zero capacity, so it launches nothing and costs nothing
until capacity is raised explicitly.

Rollback behaviour was then verified by forcing a failure after both target groups had been
created (defect 4 above), confirming automatic cleanup, a successful retry, and that
`CLONE_ROLLBACK_ON_FAILURE=false` correctly preserves partial resources instead.

## Terraform edition

The 14 Terraform modules were validated to the same standard as the CloudFormation
templates: `terraform fmt`, `validate`, `tflint` and `checkov` across all 16 configurations
(14 modules plus 2 examples), then a live apply into a third sandbox VPC (`10.44.0.0/16`),
functional checks, an idempotency re-plan, and `terraform destroy`.

**The `examples/complete` apply created 50 resources in one run.**

### Defects found

Both surfaced on the first `terraform plan` and are the same class of bug — `count` and
`for_each` cannot depend on a value that is unknown until apply.

**9. The WAF module could not be attached to a load balancer created in the same apply.**
`aws_wafv2_web_acl_association` used `for_each = toset(var.associated_resource_arns)`.
`for_each` derives its instance keys from the *values*, so an ARN produced in the same run
fails at plan time:

```
The "for_each" set includes values derived from resource attributes that cannot be
determined until apply, and so Terraform cannot determine the full set of keys...
```

That broke the primary use case — wiring WAF to a new ALB. **Fixed:** switched to
`count = length(...)`, which needs only the list length, known at plan time. The same trap
was present on `aws_lb_listener_certificate` for additional certificates and was fixed the
same way.

**10. The alarms module had the same fault.** `count = var.target_group_full_name == "" ? 0 : 1`
tested a string that comes from the ALB created in the same apply. **Fixed:** alarm creation
is now gated on explicit `enable_target_group_alarms` and `enable_waf_alarm` booleans the
caller sets statically.

**11. A new VPC's default security group was left permissive.** Flagged by checkov
(CKV2_AWS_12) and legitimate: a new VPC's default group allows unrestricted traffic between
any members. **Fixed:** the complete example now strips it to zero rules via
`aws_default_security_group`. Verified after apply — the `default` group has no ingress and
no egress.

### Improvements made during the port

- **`BucketOwnerEnforced` on the ALB log bucket**, replacing `BucketOwnerPreferred`. ACLs are
  disabled entirely, which is AWS's current guidance. Verified live: the ALB accepted the
  bucket and AWS wrote its own `ELBAccessLogTestFile` delivery-validation object, which is
  proof the bucket policy is correct.
- **State bucket lifecycle.** Versioning without expiry grows without bound; superseded
  versions now expire and incomplete multipart uploads are aborted.
- **WAF request logging** with `authorization` and `cookie` redacted — verified live. The
  CloudFormation edition had no WAF logging and, despite the filename, no WAF alarm either.
- **Guardrail Lambda hardening**: reserved concurrency, optional X-Ray tracing, optional dead
  letter queue. A guardrail that silently stops working is worse than none.

### Live results

| Check | Result |
|---|---|
| `terraform apply` | **50 resources created** |
| HTTP/80 redirect | **301** |
| HTTPS, allowed host | **503** — forwarded, not 403 |
| HTTPS, unknown host | **403 "Host not allowed"** |
| ALB attributes | drop-invalid-headers **true**, desync **defensive**, access logs **true** |
| TLS policy | **ELBSecurityPolicy-TLS13-1-2-2021-06** |
| WAF association | **vsdt-tf-webacl** |
| WAF logging | **aws-waf-logs-vsdt-tf-webacl**, redacting `authorization` and `cookie` |
| Bucket ownership | **BucketOwnerEnforced**, log delivery confirmed |
| Default security group | **zero rules** |
| Guardrail (AUDIT) | **NONCOMPLIANT logged 3 seconds** after a public SSH rule was planted |
| Idempotency re-plan | **"No changes"** — exit code 0 |
| `terraform destroy` | **50 destroyed**, sweep confirmed nothing left |

## An incidental real finding

While validating the audit script it reported a genuine issue in the test account, unrelated to
this work:

```
sg-0xxxxxxxxxxxxxxxx   sgr-0xxxxxxxxxxxxxxxx   22   22   0.0.0.0/0
```

A security group left over from an old project, tagged `Environment=production`, with SSH open
to the internet. It is attached to **no** network interface, so there is no live exposure — but
it is exactly the class of finding this toolkit exists to surface, and it was found on the first
run. The identifiers are redacted because the account is a real one; the finding is not.

This is also why the free [`aws-baseline-audit`](README.md) script grades an *attached* public
SSH rule as CRITICAL and an orphaned one as MEDIUM. A scanner that calls both the same thing
trains you to ignore it.

## Teardown

All sandbox resources were deleted after validation. From the first round: 10 CloudFormation
stacks, the test ALB and target group, the imported ACM certificate, the throwaway security
group, and the sandbox VPC with its subnets, internet gateway, and route table. From the clone
round: 4 CloudFormation stacks, the source and cloned target groups, both cloned launch
templates, the source and cloned ASGs, and the second sandbox VPC. From the Terraform round:
all 50 resources via `terraform destroy`, plus the third sandbox VPC. A resource sweep after
each round confirmed nothing remained.

## Reproducing this

Every gate in the summary table is re-runnable by anyone who has the kit. The static pass is
one command:

```bash
bash scripts/validate/validate-toolkit.sh
find scripts -name '*.sh' -print0 | xargs -0 shellcheck -s bash
actionlint
```

The AWS-side checks follow `docs/SANDBOX-TEST-PLAN.md`, which ships with the kit and is written
to be run against a disposable account — the same plan that produced this report.

---

## Why this report is public

Most infrastructure code is sold on a description of what it does. This is the evidence instead:
what was executed, what broke, and what changed as a result. Eleven defects are listed above
because they were found by deploying the thing, not by reading it — six would have failed on
first use, and one took an application offline while printing success and exiting 0.

The standing rule for the kit is that **no component is described as validated without a live
deploy behind it.** That rule is why this report names a version and a date rather than claiming
to describe the current release — see *Scope of this report* above. A re-run against v0.12.0 is
owed, and until it exists this document does not pretend to cover it.

- **Free, read-only audit script:** [`aws-baseline-audit`](README.md) — finds the problems, changes nothing
- **The kit itself:** [V's AWS Hardening Kit](https://buy.polar.sh/polar_cl_jGgPOVomjLFaKbhtmpMMHaxoywwan9TpAeGT52hUFsX) — the CloudFormation templates, Terraform modules, retrofit scripts and guides this report covers

Questions about anything in here: open an issue on this repository.
