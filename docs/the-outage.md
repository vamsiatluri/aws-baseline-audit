# My own AWS hardening script took a load balancer offline

I spent a while building a toolkit for hardening AWS infrastructure. CloudFormation
templates for a locked-down ALB, WAF, no-SSH security groups, an event-driven guardrail
Lambda — and, because most real work is on infrastructure that already exists, a set of
scripts to retrofit all of that onto load balancers already serving traffic.

It passed every static check. `cfn-lint` clean, ShellCheck clean, YAML valid. So I did
the thing I should have done first: I built a sandbox VPC and actually ran it.

It broke in six different ways. This is the one that mattered.

## The script

`harden-existing-alb.sh` takes a load balancer that is already serving traffic and
applies a default-deny posture:

1. Turn on invalid-header dropping and defensive desync mitigation
2. Make sure an HTTPS listener exists
3. Move the existing forward action behind a host-header allow rule
4. Make HTTP/80 redirect to HTTPS
5. Set the HTTPS default action to `403`

Step 5 is the point. Most load balancers forward anything that reaches them. After this,
only hostnames you explicitly listed get through, and everything else gets a 403.

Step 3 is what keeps the site up while you do it.

## The test

I built a deliberately old-fashioned load balancer to retrofit: one HTTP listener on
port 80, forwarding straight to a target group. No HTTPS at all. This is an extremely
common starting state — it is what you get from a decade-old stack, or from someone
terminating TLS somewhere else, or from a service that was internal until it wasn't.

Then I ran the script.

```
Created HTTPS listener: arn:aws:elasticloadbalancing:...
WARNING: No default forward target group found. Add an allowed-host forward rule manually.
ALB hardening complete. Validate hostname routing and health before production use.
```

Exit code 0.

## What actually happened

```bash
curl -sk -o /dev/null -w "%{http_code}\n" -H "Host: sandbox.vsdt.example.com" "https://$ALB/"
403
```

That is a request on an **allowed** hostname. The one hostname I had explicitly told the
script to permit. It got a 403.

```bash
aws elbv2 describe-target-groups --target-group-arns "$TG" --query 'TargetGroups[0].LoadBalancerArns'
[]
```

The target group was attached to nothing. The application was completely unreachable.

Port 80 had been rewritten from `forward` to `redirect`, port 443 had been created with a
`403` default action, and the target group that had been serving all the traffic was never
carried across to either of them. Every request now got redirected to HTTPS and then
refused.

## The bug

The script looked for the current forward target group in exactly one place:

```bash
# Capture an existing default forward action before changing default to deny.
CURRENT=$(aws elbv2 describe-listeners --region "$REGION" --listener-arns "$HTTPS_ARN" --output json)
TG=$(jq -r '.Listeners[0].DefaultActions[]? | select(.Type=="forward") | .TargetGroupArn // .ForwardConfig.TargetGroups[0].TargetGroupArn // empty' <<<"$CURRENT" | head -1)
```

That comment is mine, from the original. "Before changing default to deny" was the
intent. The code did not do it.

The **HTTPS** listener. On an HTTP-only load balancer there wasn't one — the script had
just created it, moments earlier, with a `403` fixed-response as its default action.

So `TG` was empty. And because it was empty, the block that creates the host-header allow
rule was skipped:

```bash
if [[ -n "$TG" ]]; then
  # create the rule that forwards allowed hosts to the target group
else
  echo "WARNING: No default forward target group found. Add an allowed-host forward rule manually."
fi
```

Then execution continued to the line that sets the HTTPS default action to 403.

Read the order again, because the ordering is the whole bug. The script:

1. created a listener whose default action is *deny*
2. looked at that listener to find out what to *allow*
3. found nothing, printed a warning
4. carried on and made the deny permanent
5. reported success

## Three things I got wrong

**I looked for state after I had already changed it.** The script created the HTTPS
listener and then queried it to discover the existing routing. By that point the thing it
was looking for could not be there. Any discovery has to happen before the first mutation,
not partway through.

**I warned about a problem I had already caused.** "Add an allowed-host forward rule
manually" is reasonable advice — a minute earlier. Printed after the default action has
been flipped to 403, it is a description of an outage that is already happening. A warning
that arrives after the damage is a log line, not a safeguard.

**I exited 0.** This is the part that would have hurt most. Anyone running this from a
pipeline sees a green step. Whatever runs next proceeds normally. The first real signal is
customers.

## The fix

Three changes, all about ordering:

**Discover before mutating, and look in both places.** The target group is now read from
the HTTPS listener *or* the HTTP listener, before anything is modified:

```bash
TG="$(tg_from_listener "$HTTPS_ARN")"
if [[ -z "$TG" ]]; then
  TG="$(tg_from_listener "$HTTP_ARN")"
fi
```

**Create the allow rule before the deny.** There is now no window in which the default is
403 and no rule forwards the allowed hostname.

**Refuse to proceed rather than black-hole traffic.** If no target group can be found
anywhere and no host rule already exists, the script stops without touching routing:

```
ERROR: No forward target group found on HTTPS/443 or HTTP/80, and no existing
       host-header forward rule is present.

Hardening would set the HTTPS default action to 403 with nothing forwarding
traffic, which would take the application offline. No changes have been made.
```

Plus a `--dry-run` flag, which is what I should have written first.

Re-running against the same HTTP-only load balancer now:

| Request | Before | After |
|---|---|---|
| HTTP, allowed host | 301 | 301 |
| HTTPS, allowed host | **403 — outage** | **503 — forwarded to the preserved target group** |
| HTTPS, unknown host | 403 | 403 |
| Target group attachment | **orphaned** | **still attached** |

The 503 is correct: the rule matched and forwarded, and my sandbox target group had no
registered instances. With real targets it is a 200. The important part is that it is no
longer a 403.

## The wider lesson

Static analysis told me this script was fine. It is syntactically valid, ShellCheck-clean
bash that makes correct AWS API calls in a sensible order. Every individual call succeeded.
The load balancer ended up in exactly the state the code described.

That state was an outage.

There is no linter for "this sequence of individually correct operations leaves the system
serving 403 to everyone." The only thing that finds it is running the thing against real
infrastructure in a state you did not design for — and then checking the outcome from the
outside, as a user, rather than checking that your commands returned 0.

I now treat "it exited 0" as roughly no evidence at all.

## Why this repo exists

`aws-baseline-audit` is the read-only half of that toolkit, extracted and given away.

It exists because the expensive part of this story was not writing the fix. It was not
knowing the problem was there. The audit runs in thirty seconds, changes nothing, and
tells you which load balancers are serving plaintext, which security groups have SSH
open to the world, and — importantly — which of those are actually reachable.

The first time I ran it against my own account it found a security group tagged
`production` with SSH open to `0.0.0.0/0`. Unattached, so not a live exposure. Still not
something I knew about.

← [Back to the README](../README.md)
