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
DRY_RUN=false
TEARDOWN=false
STATUS=false
TAG_KEY="apex-distro-vulntest"
TAG_VALUE="$(date +%Y%m%d-%H%M)"
EMAIL="${JOSH_EMAIL:-josh@pensarai.com}"

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

    # Header — runs as root via cloud-init
    cat <<'USERDATA_HEADER'
#!/bin/bash
set -x
exec > /var/log/apex-vulntest.log 2>&1
USERDATA_HEADER

    # Inject secrets/config (not single-quoted — we WANT expansion here)
    cat <<USERDATA_VARS
export PENSAR_API_KEY="${PENSAR_API_KEY}"
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
apt-get install -y curl unzip git build-essential gcc make
BLOCK
            ;;
        yum)
            cat <<'BLOCK'
yum update -y
yum install -y curl unzip git gcc make
yum groupinstall -y "Development Tools" || true
BLOCK
            ;;
        dnf)
            cat <<'BLOCK'
dnf update -y
dnf install -y curl unzip git gcc make
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
export PATH="$HOME/.pensar/bin:$PATH"

# Verify installation
which pensar || {
    for p in /root/.pensar/bin /home/*/.pensar/bin /usr/local/bin; do
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

# Write the prompt file
cat > /tmp/apex-vulntest-prompt.md <<'PROMPT_EOF'
You are performing a deep security audit of this Linux system. Your goal is to find CRITICAL severity vulnerabilities — real, exploitable issues that would represent a serious security risk in production. Do not stop until you have found at least one critical vulnerability with a working proof of concept.

## Scope

You have full root access to this system. The target is the system itself — the OS, its configuration, installed packages, running services, kernel, and any exposed network services. This is a local privilege escalation and system hardening audit.

## What counts as critical

Only report findings that meet ALL of these criteria:
- CVSS 9.0+ or equivalent real-world impact
- Exploitable (you must demonstrate exploitation or provide a working PoC)
- Not just a missing patch — must be an actual exploitable condition on THIS system

Examples of what qualifies:
- Kernel exploits with working local privilege escalation (verify the kernel version is actually vulnerable, compile and test the exploit)
- SUID/SGID binaries that can be abused for privilege escalation (GTFOBins-style, but verify they actually work)
- Writable system files that allow arbitrary code execution as root (cron jobs, init scripts, library paths)
- Services running as root with exploitable vulnerabilities (not just "old version", actually exploit it)
- Container/sandbox escape vectors if running in a container
- Cryptographic weaknesses that allow credential recovery (weak SSH keys, predictable entropy)
- Capabilities on binaries that allow privilege escalation
- Exploitable race conditions in privileged operations
- Writable LD_PRELOAD / LD_LIBRARY_PATH injection into privileged processes
- Sudo misconfigurations that allow full root from unprivileged users
- Kernel module loading from writable paths

## What does NOT count

Do not waste time on:
- Informational findings (missing headers, version disclosure)
- Low/medium severity issues
- Theoretical vulnerabilities without a working exploit
- "Best practice" recommendations
- Missing patches without confirmed exploitability on this exact system
- Default SSH configurations that are standard
- Package version enumeration without exploitation

## Methodology

Work systematically through these attack surfaces in order of likely impact:

1. **Kernel analysis**: Get exact kernel version, check for known local privilege escalation CVEs. If the kernel is old enough to be vulnerable (e.g., dirty pipe, dirty cow, overlayfs, netfilter, io_uring), download, compile, and test the exploit.
2. **SUID/SGID audit**: Find all SUID/SGID binaries, cross-reference with GTFOBins, test each viable candidate for privilege escalation.
3. **Sudo configuration**: Check sudoers for misconfigurations, NOPASSWD entries, wildcard abuse, env_keep abuse.
4. **Capabilities audit**: Find binaries with dangerous capabilities (cap_setuid, cap_dac_override, cap_sys_admin, cap_net_raw, etc.).
5. **Service enumeration**: Identify all listening services, check for exploitable versions, attempt exploitation.
6. **File permission audit**: Find world-writable files in privileged paths, writable cron jobs, init scripts, systemd units.
7. **Credential hunting**: Search for hardcoded credentials, SSH keys with weak permissions, database passwords, API tokens in config files.
8. **Library injection**: Check for writable paths in LD_LIBRARY_PATH, RPATH, RUNPATH of SUID/privileged binaries.
9. **Container/namespace analysis**: If containerized, look for escape vectors (mounted docker socket, privileged mode, etc.).
10. **Scheduled task abuse**: Writable scripts called by cron, systemd timers, at jobs running as root.
11. **Package vulnerability exploitation**: Check installed packages for CVEs with known public exploits, then actually exploit them.

## When you find a critical vulnerability

For each critical finding:
1. Document the exact vulnerability with CVE if applicable
2. Show the full exploitation steps as a reproducible PoC
3. Demonstrate impact (e.g., gained root shell, read /etc/shadow, wrote to protected file)
4. Use `document_vulnerability` to formally log it with severity CRITICAL

## Email report

After finding critical vulnerabilities, use the `send_email` tool to email a report to REPORT_EMAIL_PLACEHOLDER.

- Subject: "[APEX CRITICAL] DISTRO_NAME_PLACEHOLDER - Critical vulnerabilities found"
- Body: For each critical finding, include the vulnerability name/CVE, affected component, full exploitation steps, and demonstrated impact. Include the complete PoC commands so they can be reproduced.

Do NOT send an email until you have confirmed at least one critical vulnerability with a working proof of concept. Do not email low/medium findings.

## Important

- Be thorough and creative. Think like a real attacker performing a local privilege escalation assessment.
- If your first approach doesn't yield results, pivot to different attack surfaces.
- Compile and test kernel exploits — don't just check version numbers.
- Do NOT stop until you have found and verified at least one critical vulnerability with a working proof of concept.
PROMPT_EOF

# Substitute placeholders with actual values
sed -i "s|REPORT_EMAIL_PLACEHOLDER|${REPORT_EMAIL}|g" /tmp/apex-vulntest-prompt.md
sed -i "s|DISTRO_NAME_PLACEHOLDER|${DISTRO_NAME}|g" /tmp/apex-vulntest-prompt.md

echo "=== Starting Apex vuln test on ${DISTRO_NAME} at $(date) ==="
pensar -p @/tmp/apex-vulntest-prompt.md --target localhost 2>&1 | tee /var/log/apex-session.log
echo "=== Apex completed at $(date) ==="
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
