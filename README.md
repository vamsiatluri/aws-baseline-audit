# aws-baseline-audit

A single-file, read-only posture check for your AWS edge. No install, no agent, no
account signup, no data leaves your machine.

```bash
curl -fsSL https://raw.githubusercontent.com/vamsiatluri/aws-baseline-audit/main/aws-baseline-audit.sh -o aws-baseline-audit.sh
bash aws-baseline-audit.sh --region us-east-1
```

Every AWS call it makes is a `Describe` or `Get`. **It cannot change anything.**

## What it looks like

```
aws-baseline-audit 1.0.0
account 123456789012
read-only: no changes are made

── us-east-1 ──
  Application load balancers: 1
  Security group rules exposing SSH/RDP publicly: 1
  Running instances: 4 (SSM-managed: 1)

Findings
────────
CRITICAL my-alb  1 HTTP listener(s) serve traffic instead of redirecting to HTTPS
         us-east-1 / http-not-redirected
HIGH     my-alb  routing.http.drop_invalid_header_fields.enabled=false
         us-east-1 / invalid-headers
HIGH     my-alb  listener uses ELBSecurityPolicy-2016-08 (permits TLS 1.0/1.1)
         us-east-1 / tls-policy
HIGH     my-alb  internet-facing load balancer has no WAF Web ACL
         us-east-1 / no-waf
MEDIUM   sg-07c1c36d  ports 22-22 open to 0.0.0.0/0, attached to nothing — delete it
         us-east-1 / public-admin-port-unattached
LOW      my-alb  access logging is disabled
         us-east-1 / access-logs

Summary: 1 critical, 3 high, 1 medium, 1 low
```

## What it checks

**Load balancers** — HTTP listeners that forward instead of redirecting to HTTPS, TLS
policies that still permit 1.0/1.1, invalid-header dropping, desync mitigation mode,
WAF association on internet-facing load balancers, access logging.

**Security groups** — SSH and RDP open to `0.0.0.0/0` or `::/0`, including rules that
span those ports in a wider range.

**Compute** — running instances that are not reachable through SSM Session Manager,
which usually means you are still depending on SSH.

## The one thing most tools get wrong

A security group with SSH open to the world that is **attached to nothing** is not a
live exposure. It is still worth deleting, but it should not wake anyone up.

This tool checks attachment and grades accordingly:

- attached to a network interface → **CRITICAL**, someone can reach it right now
- attached to nothing → **MEDIUM**, a loaded gun, clean it up

Scanners that report both as the same severity train you to ignore them.

## Options

```
-r, --region REGION[,REGION...]  Regions to audit (default: your configured region)
    --all-regions                Audit every enabled region
    --profile NAME               AWS profile to use
    --json                       Machine-readable output
    --strict                     Exit 1 if any CRITICAL finding is present
```

## Use it in CI

`--strict` exits non-zero on any CRITICAL finding, so it works as a gate:

```yaml
- name: AWS baseline audit
  run: bash aws-baseline-audit.sh --region us-east-1 --strict
```

`--json` gives you the findings as structured data:

```bash
bash aws-baseline-audit.sh --all-regions --json | jq '.findings[] | select(.severity=="CRITICAL")'
```

## Requirements

AWS CLI v2, `jq`, and `bash` 3.2 or newer — stock macOS bash works. Read permissions
for `elasticloadbalancing`, `ec2`, `wafv2` and `ssm`. Missing permissions cause that
section to be skipped, not the run to fail.

## Why this exists

I wrote a toolkit for hardening AWS infrastructure, then deployed it to a real account
to check it worked. It didn't, in six different ways — including a retrofit script that
took a load balancer completely offline while printing "complete" and exiting 0.

This audit script is the read-only part of that toolkit, extracted and given away,
because finding out what is actually wrong should not cost anything.

The full kit — CloudFormation templates and Terraform modules for the hardened
baseline, plus the scripts that *fix* what this finds — is
**V's AWS Hardening Kit**. See [below](#fixing-what-it-finds).

## Fixing what it finds

| Finding | Fix |
|---|---|
| `http-not-redirected` | Convert the listener to a 301 redirect. Careful: doing this on a live ALB without carrying the target group across takes the site down. |
| `no-waf` | Attach a WAFv2 Web ACL with the AWS managed rule groups. |
| `tls-policy` | Move to `ELBSecurityPolicy-TLS13-1-2-2021-06`. Clients that cannot do TLS 1.2 will stop connecting. |
| `invalid-headers` / `desync-mitigation` | Set the attributes; both are safe to change in place. |
| `public-admin-port` | Revoke the rule and move administration to SSM Session Manager. |
| `ssm-coverage` | Attach an instance profile with `AmazonSSMManagedInstanceCore`, and make sure private subnets can reach the SSM endpoints. |

All of these are automated, with dry-run support and rollback notes, in
**V's AWS Hardening Kit** — 14 CloudFormation templates, 14 Terraform modules, 9 scripts
and 25 how-to guides, every one of them deployed to a live AWS account and exercised
before release.

*Launching shortly. Watch this repo to hear about it.*

## License

MIT. See [LICENSE](LICENSE).

## Contributing

Issues and pull requests welcome. If you add a check, it must stay read-only: no
mutating API call belongs in this script.
