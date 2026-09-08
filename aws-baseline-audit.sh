#!/usr/bin/env bash
#
# aws-baseline-audit — a read-only AWS edge and access posture check.
#
# Reports on load balancers, security groups and SSM coverage. Makes no
# changes: every AWS call it issues is a Describe/Get.
#
# MIT licensed. https://github.com/vamsiatluri/aws-baseline-audit
#
set -euo pipefail

VERSION="1.0.0"

export AWS_PAGER=""
# jq needs JSON. A profile configured with `output = yaml|text|table` would
# otherwise break every parse below with "jq: parse error".
export AWS_DEFAULT_OUTPUT=json

REGIONS=""
FORMAT="text"
STRICT=0
PROFILE_ARG=()

usage() {
  cat <<USAGE
aws-baseline-audit $VERSION — read-only AWS posture check

Usage: $0 [options]

Options:
  -r, --region REGION[,REGION...]  Regions to audit (default: current region)
      --all-regions                Audit every enabled region
      --profile NAME               AWS profile to use
      --json                       Emit JSON instead of a report
      --strict                     Exit 1 if any CRITICAL finding is present
  -h, --help                       Show this help
  -v, --version                    Show version

What it checks:
  Load balancers   HTTP->HTTPS redirect, TLS policy, invalid-header dropping,
                   desync mitigation, WAF association, access logging
  Security groups  SSH/RDP open to the internet, and whether the group is
                   actually attached to anything
  Compute          Instances not reachable via SSM Session Manager

Read-only. It issues no mutating API calls.

Examples:
  $0 --region us-east-1
  $0 --all-regions --strict
  $0 --region us-east-1 --json | jq '.findings[] | select(.severity=="CRITICAL")'
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -r|--region) REGIONS="$2"; shift 2 ;;
    --all-regions) REGIONS="ALL"; shift ;;
    --profile) PROFILE_ARG=(--profile "$2"); shift 2 ;;
    --json) FORMAT="json"; shift ;;
    --strict) STRICT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -v|--version) echo "$VERSION"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

for cmd in aws jq; do
  command -v "$cmd" >/dev/null || { echo "ERROR: $cmd is required but not installed." >&2; exit 2; }
done

aws_() { aws "${PROFILE_ARG[@]+"${PROFILE_ARG[@]}"}" "$@"; }

if [[ "$REGIONS" == "ALL" ]]; then
  REGION_LIST=$(aws_ ec2 describe-regions --query 'Regions[].RegionName' --output text | tr '\t' '\n')
elif [[ -n "$REGIONS" ]]; then
  REGION_LIST=$(echo "$REGIONS" | tr ',' '\n')
else
  REGION_LIST=$(aws_ configure get region || echo "us-east-1")
fi

ACCOUNT=$(aws_ sts get-caller-identity --query Account --output text)

FINDINGS_FILE=$(mktemp)
trap 'rm -f "$FINDINGS_FILE"' EXIT

# severity | region | resource | check | detail
finding() {
  printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >> "$FINDINGS_FILE"
}

C_RED=''; C_YEL=''; C_GRN=''; C_DIM=''; C_OFF=''
if [[ -t 1 && "$FORMAT" == "text" ]]; then
  C_RED=$'\033[31m'; C_YEL=$'\033[33m'; C_GRN=$'\033[32m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
fi

say() { if [[ "$FORMAT" == "text" ]]; then echo "$@"; fi; }

# ---------------------------------------------------------------------------
# Load balancers
# ---------------------------------------------------------------------------
audit_load_balancers() {
  local region="$1" lbs
  lbs=$(aws_ elbv2 describe-load-balancers --region "$region" 2>/dev/null || echo '{"LoadBalancers":[]}')

  local count
  count=$(jq '[.LoadBalancers[] | select(.Type=="application")] | length' <<<"$lbs")
  say "  Application load balancers: $count"

  [[ "$count" -eq 0 ]] && return 0

  while IFS=$'\t' read -r name arn scheme; do
    [[ -z "$name" ]] && continue
    local attrs listeners waf
    attrs=$(aws_ elbv2 describe-load-balancer-attributes --region "$region" --load-balancer-arn "$arn")
    listeners=$(aws_ elbv2 describe-listeners --region "$region" --load-balancer-arn "$arn")

    local drop desync logs
    drop=$(jq -r '.Attributes[]|select(.Key=="routing.http.drop_invalid_header_fields.enabled").Value' <<<"$attrs")
    desync=$(jq -r '.Attributes[]|select(.Key=="routing.http.desync_mitigation_mode").Value' <<<"$attrs")
    logs=$(jq -r '.Attributes[]|select(.Key=="access_logs.s3.enabled").Value' <<<"$attrs")

    [[ "$drop" == "true" ]]      || finding HIGH "$region" "$name" "invalid-headers" "routing.http.drop_invalid_header_fields.enabled=$drop"
    [[ "$desync" == "defensive" || "$desync" == "strictest" ]] || finding MEDIUM "$region" "$name" "desync-mitigation" "mode=$desync"
    [[ "$logs" == "true" ]]      || finding LOW "$region" "$name" "access-logs" "access logging is disabled"

    # An HTTP listener that forwards rather than redirects serves plaintext.
    local http_forwards
    http_forwards=$(jq -r '[.Listeners[]|select(.Protocol=="HTTP")|select([.DefaultActions[].Type]|index("redirect")|not)]|length' <<<"$listeners")
    [[ "$http_forwards" -eq 0 ]] || finding CRITICAL "$region" "$name" "http-not-redirected" "$http_forwards HTTP listener(s) serve traffic instead of redirecting to HTTPS"

    # Weak or dated TLS policies.
    while read -r pol; do
      [[ -z "$pol" || "$pol" == "null" ]] && continue
      case "$pol" in
        *TLS13*|*TLS-1-2*) : ;;
        *) finding HIGH "$region" "$name" "tls-policy" "listener uses $pol (permits TLS 1.0/1.1)" ;;
      esac
    done < <(jq -r '.Listeners[]|select(.Protocol=="HTTPS")|.SslPolicy' <<<"$listeners")

    if [[ "$scheme" == "internet-facing" ]]; then
      waf=$(aws_ wafv2 get-web-acl-for-resource --region "$region" --resource-arn "$arn" 2>/dev/null | jq -r '.WebACL.Name // empty')
      [[ -n "$waf" ]] || finding HIGH "$region" "$name" "no-waf" "internet-facing load balancer has no WAF Web ACL"
    fi
  done < <(jq -r '.LoadBalancers[]|select(.Type=="application")|[.LoadBalancerName,.LoadBalancerArn,.Scheme]|@tsv' <<<"$lbs")
}

# ---------------------------------------------------------------------------
# Security groups
# ---------------------------------------------------------------------------
audit_security_groups() {
  local region="$1" rules
  rules=$(aws_ ec2 describe-security-group-rules --region "$region" 2>/dev/null || echo '{"SecurityGroupRules":[]}')

  local open
  open=$(jq -r '
    .SecurityGroupRules[]
    | select(.IsEgress==false)
    | select(.IpProtocol=="tcp" or .IpProtocol=="-1")
    | select((.CidrIpv4=="0.0.0.0/0") or (.CidrIpv6=="::/0"))
    | select((.IpProtocol=="-1") or ((.FromPort<=22 and .ToPort>=22) or (.FromPort<=3389 and .ToPort>=3389)))
    | [.GroupId,.SecurityGroupRuleId,(.FromPort//"all"|tostring),(.ToPort//"all"|tostring),(.CidrIpv4//.CidrIpv6)]
    | @tsv' <<<"$rules")

  local n=0
  while IFS=$'\t' read -r gid rid from to cidr; do
    [[ -z "$gid" ]] && continue
    n=$((n+1))
    # An unattached group is a loaded gun, not a live exposure. Report the
    # difference -- it changes how urgently you should act.
    local enis
    enis=$(aws_ ec2 describe-network-interfaces --region "$region" \
             --filters Name=group-id,Values="$gid" \
             --query 'length(NetworkInterfaces)' --output text 2>/dev/null || echo 0)
    local port_desc="ports ${from}-${to}"
    [[ "$from" == "all" ]] && port_desc="ALL ports"
    if [[ "$enis" -gt 0 ]]; then
      finding CRITICAL "$region" "$gid" "public-admin-port" "$port_desc open to $cidr, ATTACHED to $enis interface(s) — live exposure ($rid)"
    else
      finding MEDIUM "$region" "$gid" "public-admin-port-unattached" "$port_desc open to $cidr, attached to nothing — delete it ($rid)"
    fi
  done <<<"$open"
  say "  Security group rules exposing SSH/RDP publicly: $n"
}

# ---------------------------------------------------------------------------
# SSM coverage
# ---------------------------------------------------------------------------
audit_ssm() {
  local region="$1" running managed
  running=$(aws_ ec2 describe-instances --region "$region" \
    --filters Name=instance-state-name,Values=running \
    --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null | tr '\t' '\n' | grep -c . || true)
  # shellcheck disable=SC2016  # backticks are JMESPath literals for --query, not shell substitution
  managed=$(aws_ ssm describe-instance-information --region "$region" \
    --query 'InstanceInformationList[?PingStatus==`Online`].InstanceId' --output text 2>/dev/null | tr '\t' '\n' | grep -c . || true)
  say "  Running instances: $running (SSM-managed: $managed)"
  if [[ "$running" -gt "$managed" ]]; then
    finding MEDIUM "$region" "ec2" "ssm-coverage" "$((running-managed)) running instance(s) are not reachable via SSM Session Manager"
  fi
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
if [[ "$FORMAT" == "text" ]]; then
  echo
  echo "aws-baseline-audit $VERSION"
  echo "account $ACCOUNT"
  echo "${C_DIM}read-only: no changes are made${C_OFF}"
fi

for region in $REGION_LIST; do
  [[ -z "$region" ]] && continue
  say ""
  say "${C_DIM}── $region ──${C_OFF}"
  audit_load_balancers "$region" || say "  (load balancer audit skipped: access denied)"
  audit_security_groups "$region" || say "  (security group audit skipped: access denied)"
  audit_ssm "$region" || say "  (SSM audit skipped: access denied)"
done

CRIT=$(awk -F'\t' '$1=="CRITICAL"' "$FINDINGS_FILE" | wc -l | tr -d ' ')
HIGH=$(awk -F'\t' '$1=="HIGH"' "$FINDINGS_FILE" | wc -l | tr -d ' ')
MED=$(awk -F'\t'  '$1=="MEDIUM"' "$FINDINGS_FILE" | wc -l | tr -d ' ')
LOW=$(awk -F'\t'  '$1=="LOW"' "$FINDINGS_FILE" | wc -l | tr -d ' ')

if [[ "$FORMAT" == "json" ]]; then
  jq -Rn --arg account "$ACCOUNT" --arg version "$VERSION" \
     --argjson c "$CRIT" --argjson h "$HIGH" --argjson m "$MED" --argjson l "$LOW" '
    {
      version: $version,
      account: $account,
      summary: {critical:$c, high:$h, medium:$m, low:$l},
      findings: [inputs | split("\t") | {severity:.[0], region:.[1], resource:.[2], check:.[3], detail:.[4]}]
    }' < "$FINDINGS_FILE"
else
  echo
  if [[ $((CRIT+HIGH+MED+LOW)) -eq 0 ]]; then
    echo "${C_GRN}No findings.${C_OFF}"
  else
    echo "Findings"
    echo "────────"
    for sev in CRITICAL HIGH MEDIUM LOW; do
      colour="$C_DIM"
      [[ "$sev" == "CRITICAL" ]] && colour="$C_RED"
      [[ "$sev" == "HIGH" ]] && colour="$C_RED"
      [[ "$sev" == "MEDIUM" ]] && colour="$C_YEL"
      while IFS=$'\t' read -r s r res chk det; do
        [[ -z "$s" ]] && continue
        printf '%s%-8s%s %s  %s\n' "$colour" "$s" "$C_OFF" "$res" "$det"
        printf '         %s%s / %s%s\n' "$C_DIM" "$r" "$chk" "$C_OFF"
      done < <(awk -F'\t' -v s="$sev" '$1==s' "$FINDINGS_FILE")
    done
  fi
  echo
  printf 'Summary: %s%d critical%s, %s%d high%s, %s%d medium%s, %d low\n' \
    "$C_RED" "$CRIT" "$C_OFF" "$C_RED" "$HIGH" "$C_OFF" "$C_YEL" "$MED" "$C_OFF" "$LOW"
  echo
fi

if [[ $STRICT -eq 1 && "$CRIT" -gt 0 ]]; then
  exit 1
fi
exit 0
