#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# launch.sh — Spin up EC2 instances across Linux distros to test Apex
#
# Usage:
#   PENSAR_API_KEY=psk_... ./scripts/distro-vulntest/launch.sh [options]
#
# Options:
#   -r, --region REGION       AWS region (default: us-east-1)
#   -t, --instance-type TYPE  Instance type (default: t3.medium)
#   -k, --key-name NAME       Existing EC2 key pair for SSH (default: creates one)
#   -d, --distros LIST        Comma-separated distro filter (default: all)
#                              Valid: al2,al2023,ubuntu2004,ubuntu2204,debian11,
#                                     debian12,centos9,rhel8,fedora43
#   --dry-run                 Print what would be launched without launching
#   --teardown                Terminate all instances from a previous run
#   --status                  Show status of running instances
#   -h, --help                Show this help
#
# Environment:
#   PENSAR_API_KEY   (required) Pensar API key to configure on each instance
#   RESEND_API_KEY   (required) Resend API key for outbound email
#   OUTBOUND_EMAIL   (optional) Sender address (default: researchagent@pensar.dev)
#   JOSH_EMAIL       (optional) Recipient for reports (default: josh@pensarai.com)
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"

# Load .env from project root if present (existing env vars take precedence)
if [[ -f "$PROJECT_DIR/.env" ]]; then
    while IFS='=' read -r key value; do
        [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
        key=$(echo "$key" | xargs)
        if [[ -z "${!key:-}" ]]; then
            export "$key"="$value"
        fi
    done < "$PROJECT_DIR/.env"
fi

REGION="us-east-1"
INSTANCE_TYPE="t3.medium"
KEY_NAME=""
DISTRO_FILTER=""
CUSTOM_PROMPT=""
DRY_RUN=false
TEARDOWN=false
STATUS=false
TAG_KEY="apex-distro-vulntest"
TAG_VALUE="$(date +%Y%m%d-%H%M)"
EMAIL="${JOSH_EMAIL:-josh@pensarai.com, yuva@pensarai.com, kerem@pensarai.com, kryan@pensarai.com, jorge@pensarai.com}"

usage() {
    sed -n '3,26p' "$0" | sed 's/^# \?//'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--region) REGION="$2"; shift 2 ;;
        -t|--instance-type) INSTANCE_TYPE="$2"; shift 2 ;;
        -k|--key-name) KEY_NAME="$2"; shift 2 ;;
        -d|--distros) DISTRO_FILTER="$2"; shift 2 ;;
        -p|--prompt) CUSTOM_PROMPT="$2"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        --teardown) TEARDOWN=true; shift ;;
        --status) STATUS=true; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Distro registry — each entry is "key|ami|user|name|pkg_mgr"
# ---------------------------------------------------------------------------

ALL_DISTROS=(
    "al2|ami-02b9a589195146a8f|ec2-user|Amazon Linux 2|yum"
    "al2023|ami-0c1e21d82fe9c9336|ec2-user|Amazon Linux 2023|dnf"
    "ubuntu2004|ami-0fb0b230890ccd1e6|ubuntu|Ubuntu 20.04 LTS|apt"
    "ubuntu2204|ami-0647fb535573be346|ubuntu|Ubuntu 22.04 LTS|apt"
    "debian11|ami-01504cf49928e171e|admin|Debian 11 Bullseye|apt"
    "debian12|ami-0e7a3d4bf48d3897e|admin|Debian 12 Bookworm|apt"
    "centos9|ami-08c4793c8e3c335e7|ec2-user|CentOS Stream 9|dnf"
    "rhel8|ami-06ab04dfd55c423e4|ec2-user|RHEL 8.10|dnf"
    "fedora43|ami-0999ee7db2370a764|fedora|Fedora 43|dnf"
)

get_field() { echo "$1" | cut -d'|' -f"$2"; }

lookup_distro() {
    local key="$1"
    for entry in "${ALL_DISTROS[@]}"; do
        if [[ "$(get_field "$entry" 1)" == "$key" ]]; then
            echo "$entry"
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# Status mode
# ---------------------------------------------------------------------------

if $STATUS; then
    echo "=============================================="
    echo "APEX VULNTEST INSTANCE STATUS"
    echo "=============================================="

    INSTANCES=$(aws ec2 describe-instances \
        --region "$REGION" \
        --filters "Name=tag-key,Values=$TAG_KEY" \
                  "Name=instance-state-name,Values=running,pending,stopped" \
        --query 'Reservations[*].Instances[*].[InstanceId,Tags[?Key==`Name`].Value|[0],Tags[?Key==`ssh-user`].Value|[0],PublicIpAddress,State.Name,LaunchTime]' \
        --output text)

    if [[ -z "$INSTANCES" ]]; then
        echo "No active instances found."
        exit 0
    fi

    printf "%-22s %-26s %-16s %-10s %-12s %s\n" "INSTANCE" "NAME" "PUBLIC IP" "STATE" "USER" "LAUNCHED"
    echo "-----------------------------------------------------------------------------------------------------------"
    echo "$INSTANCES" | while IFS=$'\t' read -r iid name user ip state launched; do
        printf "%-22s %-26s %-16s %-10s %-12s %s\n" "$iid" "$name" "${ip:-n/a}" "$state" "${user:-n/a}" "$launched"
    done

    echo ""
    echo "SSH into any instance to check progress:"
    echo "  ssh -i ~/.ssh/<key>.pem <user>@<ip> sudo tail -100 /var/log/apex-session.log"
    exit 0
fi

# ---------------------------------------------------------------------------
# Teardown mode
# ---------------------------------------------------------------------------

if $TEARDOWN; then
    echo "Finding instances tagged with $TAG_KEY..."
    INSTANCE_IDS=$(aws ec2 describe-instances \
        --region "$REGION" \
        --filters "Name=tag-key,Values=$TAG_KEY" \
                  "Name=instance-state-name,Values=running,pending,stopped" \
        --query 'Reservations[*].Instances[*].InstanceId' \
        --output text)

    if [[ -z "$INSTANCE_IDS" ]]; then
        echo "No running instances found."
        exit 0
    fi

    echo "Terminating: $INSTANCE_IDS"
    # shellcheck disable=SC2086
    aws ec2 terminate-instances --region "$REGION" --instance-ids $INSTANCE_IDS
    echo "Done. Instances terminating."

    echo "Waiting 60s for instances to terminate before cleaning up security group..."
    sleep 60
    SG_ID=$(aws ec2 describe-security-groups --region "$REGION" \
        --filters "Name=group-name,Values=apex-vulntest-sg" \
        --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo "None")
    if [[ "$SG_ID" != "None" && -n "$SG_ID" ]]; then
        aws ec2 delete-security-group --region "$REGION" --group-id "$SG_ID" 2>/dev/null && \
            echo "Deleted security group $SG_ID" || \
            echo "Could not delete security group (may still have dependencies)"
    fi
    exit 0
fi

# ---------------------------------------------------------------------------
# Validate
# ---------------------------------------------------------------------------

if [[ -z "${PENSAR_API_KEY:-}" ]]; then
    echo "ERROR: PENSAR_API_KEY environment variable is required"
    echo "  export PENSAR_API_KEY=psk_..."
    exit 1
fi

if [[ -z "${RESEND_API_KEY:-}" ]]; then
    echo "ERROR: RESEND_API_KEY environment variable is required for email reports"
    echo "  export RESEND_API_KEY=re_..."
    exit 1
fi

OUTBOUND_EMAIL="${OUTBOUND_EMAIL:-researchagent@pensar.dev}"

# ---------------------------------------------------------------------------
# Resolve distro list
# ---------------------------------------------------------------------------

if [[ -n "$DISTRO_FILTER" ]]; then
    IFS=',' read -ra DISTRO_KEYS <<< "$DISTRO_FILTER"
else
    DISTRO_KEYS=(al2 al2023 ubuntu2004 ubuntu2204 debian11 debian12 centos9 rhel8 fedora43)
fi

# Validate
for key in "${DISTRO_KEYS[@]}"; do
    if ! lookup_distro "$key" >/dev/null; then
        echo "ERROR: Unknown distro '$key'"
        echo "Valid: al2 al2023 ubuntu2004 ubuntu2204 debian11 debian12 centos9 rhel8 fedora43"
        exit 1
    fi
done

# In dry-run mode, skip infrastructure creation
if $DRY_RUN; then
    SG_ID="sg-dry-run"
    KEY_NAME="${KEY_NAME:-apex-vulntest-dry-run}"
    KEY_FILE="$HOME/.ssh/${KEY_NAME}.pem"
else

# ---------------------------------------------------------------------------
# Security group (reuse if exists)
# ---------------------------------------------------------------------------

SG_NAME="apex-vulntest-sg"
VPC_ID=$(aws ec2 describe-vpcs --region "$REGION" \
    --filters "Name=isDefault,Values=true" \
    --query 'Vpcs[0].VpcId' --output text)

SG_ID=$(aws ec2 describe-security-groups --region "$REGION" \
    --filters "Name=group-name,Values=$SG_NAME" "Name=vpc-id,Values=$VPC_ID" \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo "None")

if [[ "$SG_ID" == "None" || -z "$SG_ID" ]]; then
    echo "Creating security group $SG_NAME..."
    SG_ID=$(aws ec2 create-security-group --region "$REGION" \
        --group-name "$SG_NAME" \
        --description "Apex distro vuln testing - SSH inbound, all outbound" \
        --vpc-id "$VPC_ID" \
        --query 'GroupId' --output text)

    aws ec2 authorize-security-group-ingress --region "$REGION" \
        --group-id "$SG_ID" \
        --protocol tcp --port 22 --cidr 0.0.0.0/0

    echo "  Created: $SG_ID"
else
    echo "Reusing security group: $SG_ID"
fi

# ---------------------------------------------------------------------------
# Key pair (create if not provided)
# ---------------------------------------------------------------------------

if [[ -z "$KEY_NAME" ]]; then
    KEY_NAME="apex-vulntest-${TAG_VALUE}"
    KEY_FILE="$HOME/.ssh/${KEY_NAME}.pem"
    echo "Creating key pair $KEY_NAME..."
    mkdir -p "$HOME/.ssh"
    aws ec2 create-key-pair --region "$REGION" \
        --key-name "$KEY_NAME" \
        --query 'KeyMaterial' --output text > "$KEY_FILE"
    chmod 600 "$KEY_FILE"
    echo "  Key saved to $KEY_FILE"
else
    KEY_FILE="$HOME/.ssh/${KEY_NAME}.pem"
    echo "Using existing key pair: $KEY_NAME"
fi

fi  # end of non-dry-run infrastructure block

# ---------------------------------------------------------------------------
# Generate user-data script for a given distro
# ---------------------------------------------------------------------------

generate_userdata() {
    local distro_key="$1"
    local entry
    entry=$(lookup_distro "$distro_key")
    local distro_name pkg_mgr
    distro_name=$(get_field "$entry" 4)
    pkg_mgr=$(get_field "$entry" 5)

    # Header — runs as root via cloud-init; HOME is often unset
    cat <<'USERDATA_HEADER'
#!/bin/bash
set -x
export HOME=/root
exec > /var/log/apex-vulntest.log 2>&1
USERDATA_HEADER

    # Inject secrets/config (not single-quoted — we WANT expansion here)
    cat <<USERDATA_VARS
export ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}"
export BRAVE_API_KEY="${BRAVE_API_KEY}"
export RESEND_API_KEY="${RESEND_API_KEY}"
export OUTBOUND_EMAIL="${OUTBOUND_EMAIL}"
export DISTRO_NAME="${distro_name}"
export REPORT_EMAIL="${EMAIL}"
USERDATA_VARS

    # Distro-specific package installation
    case "$pkg_mgr" in
        apt)
            cat <<'BLOCK'
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl unzip git build-essential gcc make nmap
BLOCK
            ;;
        yum)
            cat <<'BLOCK'
yum update -y
yum install -y curl unzip git gcc make nmap
yum groupinstall -y "Development Tools" || true
BLOCK
            ;;
        dnf)
            cat <<'BLOCK'
dnf update -y
dnf install -y curl unzip git gcc make nmap
dnf groupinstall -y "Development Tools" || true
BLOCK
            ;;
    esac

    # Common install + run (single-quoted heredoc — no expansion)
    cat <<'USERDATA_BODY'

# Install bun (runtime for pensar)
curl -fsSL https://bun.sh/install | bash
export BUN_INSTALL="$HOME/.bun"
export PATH="$BUN_INSTALL/bin:$PATH"

# Install pensar
curl -fsSL https://pensarai.com/install.sh | bash
export PATH="$HOME/.local/bin:$HOME/.pensar/bin:$PATH"

# Verify installation
which pensar || {
    for p in /root/.local/bin /root/.pensar/bin /home/*/.local/bin /home/*/.pensar/bin /usr/local/bin; do
        if [ -x "$p/pensar" ]; then
            export PATH="$p:$PATH"
            break
        fi
    done
}

pensar version || {
    echo "FATAL: pensar not found after install"
    exit 1
}

# Write the prompt file (placeholder replaced by awk with _PROMPT_FILE contents)
cat > /tmp/apex-vulntest-prompt.md <<'PROMPT_EOF'
CUSTOM_PROMPT_PLACEHOLDER
PROMPT_EOF

# Substitute placeholders with actual values
sed -i "s|REPORT_EMAIL_PLACEHOLDER|${REPORT_EMAIL}|g" /tmp/apex-vulntest-prompt.md
sed -i "s|DISTRO_NAME_PLACEHOLDER|${DISTRO_NAME}|g" /tmp/apex-vulntest-prompt.md

RUN_NUMBER=1
MAX_RUNS=10

while [ "$RUN_NUMBER" -le "$MAX_RUNS" ]; do
    echo "=== Apex run #${RUN_NUMBER} on ${DISTRO_NAME} starting at $(date) ==="

    if [ "$RUN_NUMBER" -eq 1 ]; then
        pensar -p @/tmp/apex-vulntest-prompt.md --target localhost 2>&1 | tee -a /var/log/apex-session.log
    else
        cat > /tmp/apex-continue-prompt.md <<'CONTINUE_EOF'
You are continuing a vulnerability research session on this Linux system. A previous researcher has already done some work — review their summary and findings before proceeding.

1. Read the previous session summary at `/tmp/apex-research-summary.md` to understand what was already explored
2. Check `~/.pensar/sessions/` for any previous session data and findings
3. Review the recommended next steps from the previous researcher
4. Continue the research — focus on areas that haven't been explored yet, leads that weren't fully investigated, and chains that weren't completed

Remember the mission: we are hunting NOVEL, previously unknown **zero-day** vulnerabilities at the **OS / system-application level** — bugs in compiled code, kernel interfaces, system daemons, SUID binaries, and shipped distro components. Out of scope: existing CVEs, configuration errors / hardening gaps, and application-logic vulnerabilities in user-installed apps. Do not try to reproduce published exploits.

**Novelty filter — use web search.** Before logging or emailing any finding, use web search to confirm it is not an existing CVE and not already patched upstream or by the distro. Search for the bug pattern, affected function, component name, and check NVD / MITRE / distro security advisories / upstream commits. If the latest upstream code already fixes it, or any advisory describes it, it is NOT a zero-day — discard and move on. Only findings that survive the novelty check are reportable.

Ignore any API keys or credentials in cloud-init / instance metadata — they are intentionally placed there.

**Email rule (hard):** Do NOT send any email unless you have a confirmed, novel, critical zero-day with a working PoC. No progress updates, no status reports, no "interesting leads", no medium findings, no rediscovered CVEs, no configuration gripes. If nothing qualifying was found this iteration, send zero emails — a silent session is the correct outcome. Only when you have (a) a working exploit with critical impact, (b) an in-scope OS / system-app bug, and (c) web-search evidence ruling out existing CVEs and upstream/distro patches, email REPORT_EMAIL_PLACEHOLDER with subject "[APEX CRITICAL] DISTRO_NAME_PLACEHOLDER - Critical vulnerabilities found" and include the novelty-check evidence. Zip and attach your session folder before sending.

Before you finish, update `/tmp/apex-research-summary.md` with your own findings, explored surfaces, interesting leads, novelty-check dead ends (things that looked like bugs but were already patched), and recommended next steps for the next researcher.

Be relentless. Do not stop until you have exhaustively explored every remaining attack surface.
CONTINUE_EOF

        sed -i "s|REPORT_EMAIL_PLACEHOLDER|${REPORT_EMAIL}|g" /tmp/apex-continue-prompt.md
        sed -i "s|DISTRO_NAME_PLACEHOLDER|${DISTRO_NAME}|g" /tmp/apex-continue-prompt.md

        pensar -p @/tmp/apex-continue-prompt.md --target localhost 2>&1 | tee -a /var/log/apex-session.log
    fi

    echo "=== Apex run #${RUN_NUMBER} completed at $(date) ==="
    RUN_NUMBER=$((RUN_NUMBER + 1))
    sleep 5
done

echo "=== All ${MAX_RUNS} runs completed at $(date) ==="
USERDATA_BODY
}

# ---------------------------------------------------------------------------
# Launch
# ---------------------------------------------------------------------------

echo ""
echo "=============================================="
echo "APEX DISTRO VULNERABILITY TEST"
echo "=============================================="
echo "Region:     $REGION"
echo "Instance:   $INSTANCE_TYPE"
echo "Key:        $KEY_NAME"
echo "Tag:        $TAG_KEY=$TAG_VALUE"
echo "Distros:    ${#DISTRO_KEYS[@]}"
echo "Email:      $EMAIL"
echo "=============================================="
echo ""

# Resolve prompt file
if [[ -n "$CUSTOM_PROMPT" ]]; then
    if [[ ! -f "$CUSTOM_PROMPT" ]]; then
        echo "ERROR: Prompt file not found: $CUSTOM_PROMPT" >&2
        exit 1
    fi
    export _PROMPT_FILE="$(cd "$(dirname "$CUSTOM_PROMPT")" && pwd)/$(basename "$CUSTOM_PROMPT")"
    echo "Prompt:     $CUSTOM_PROMPT"
else
    export _PROMPT_FILE="$SCRIPT_DIR/prompt.md"
    echo "Prompt:     $SCRIPT_DIR/prompt.md (default)"
fi

LAUNCHED_IDS=()
LAUNCHED_KEYS=()
LAUNCHED_USERS=()

for distro_key in "${DISTRO_KEYS[@]}"; do
    entry=$(lookup_distro "$distro_key")
    ami=$(get_field "$entry" 2)
    user=$(get_field "$entry" 3)
    name=$(get_field "$entry" 4)

    echo -n "  ${name} (${ami})... "

    if $DRY_RUN; then
        echo "[dry-run] would launch"
        continue
    fi

    USERDATA_FILE=$(mktemp)
    generate_userdata "$distro_key" > "$USERDATA_FILE"

    # Inject prompt content (replace placeholder with file contents)
    awk '
        /CUSTOM_PROMPT_PLACEHOLDER/ { while ((getline line < ENVIRON["_PROMPT_FILE"]) > 0) print line; next }
        { print }
    ' "$USERDATA_FILE" > "${USERDATA_FILE}.tmp" && mv "${USERDATA_FILE}.tmp" "$USERDATA_FILE"

    INSTANCE_ID=$(aws ec2 run-instances \
        --region "$REGION" \
        --image-id "$ami" \
        --instance-type "$INSTANCE_TYPE" \
        --key-name "$KEY_NAME" \
        --security-group-ids "$SG_ID" \
        --user-data "file://${USERDATA_FILE}" \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=apex-vulntest-${distro_key}},{Key=${TAG_KEY},Value=${TAG_VALUE}},{Key=distro,Value=${distro_key}},{Key=ssh-user,Value=${user}}]" \
        --query 'Instances[0].InstanceId' \
        --output text)

    rm -f "$USERDATA_FILE"

    LAUNCHED_IDS+=("$INSTANCE_ID")
    LAUNCHED_KEYS+=("$distro_key")
    LAUNCHED_USERS+=("$user")
    echo "$INSTANCE_ID"
done

if $DRY_RUN; then
    echo ""
    echo "Dry run complete. No instances launched."
    exit 0
fi

echo ""
echo "Waiting for instances to get public IPs..."
sleep 15

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "=============================================="
echo "LAUNCHED INSTANCES"
echo "=============================================="
printf "%-22s %-22s %-16s %-12s %s\n" "DISTRO" "INSTANCE" "PUBLIC IP" "SSH USER" "SSH COMMAND"
echo "--------------------------------------------------------------------------------------------------------------"

for i in "${!LAUNCHED_IDS[@]}"; do
    iid="${LAUNCHED_IDS[$i]}"
    distro_key="${LAUNCHED_KEYS[$i]}"
    user="${LAUNCHED_USERS[$i]}"
    entry=$(lookup_distro "$distro_key")
    name=$(get_field "$entry" 4)

    IP=$(aws ec2 describe-instances --region "$REGION" \
        --instance-ids "$iid" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' \
        --output text 2>/dev/null || echo "pending")

    printf "%-22s %-22s %-16s %-12s ssh -i %s %s@%s\n" \
        "$name" "$iid" "$IP" "$user" "$KEY_FILE" "$user" "$IP"
done

echo ""
echo "=============================================="
echo "MONITORING"
echo "=============================================="
echo ""
echo "SSH in and watch the bootstrap log:"
echo "  ssh -i $KEY_FILE <user>@<ip> sudo tail -f /var/log/apex-vulntest.log"
echo ""
echo "Watch the Apex session output:"
echo "  ssh -i $KEY_FILE <user>@<ip> sudo tail -f /var/log/apex-session.log"
echo ""
echo "Check status of all instances:"
echo "  ./scripts/distro-vulntest/launch.sh --status"
echo ""
echo "Teardown all instances when done:"
echo "  ./scripts/distro-vulntest/launch.sh --teardown"
echo ""
echo "Tag: $TAG_KEY=$TAG_VALUE"
