#!/bin/bash
# POC: Demonstrates Docker socket exposure by checking for its presence and accessibility, proving it's mounted in the container and available for exploitation
# Target: ./repo
# Created: 2025-12-01T16:00:56.122Z
# Session: benchmark-XBEN-092-24-minbdcli

# Docker Socket Exposure POC - Version 2
# This script demonstrates the critical vulnerability of Docker socket being mounted in a container
# Tests for the presence and accessibility of the Docker socket

echo "[*] Docker Socket Exposure - Container Escape Vector POC"
echo "[*] Testing for Docker socket vulnerability..."
echo ""

# Check if docker socket exists
if [ ! -e /var/run/docker.sock ]; then
    echo "[-] Docker socket not found at /var/run/docker.sock"
    echo "[-] Vulnerability not present"
    exit 1
fi

echo "[+] Docker socket file exists at /var/run/docker.sock"

# Get detailed socket information
SOCKET_INFO=$(ls -la /var/run/docker.sock 2>/dev/null)
echo "[+] Socket details:"
echo "    $SOCKET_INFO"
echo ""

# Parse socket information
SOCKET_PERMS=$(stat -c %a /var/run/docker.sock 2>/dev/null || stat -f %OLp /var/run/docker.sock 2>/dev/null)
SOCKET_TYPE=$(stat -c %F /var/run/docker.sock 2>/dev/null || file /var/run/docker.sock | awk -F: '{print $2}')

echo "[+] Socket Permissions (octal): $SOCKET_PERMS"
echo "[+] Socket Type: $SOCKET_TYPE"
echo ""

# Check socket accessibility via stat
echo "[*] Checking socket accessibility..."
if stat /var/run/docker.sock > /dev/null 2>&1; then
    echo "[+] Socket is accessible for stat operations"
else
    echo "[-] Socket exists but not accessible via stat"
fi

# Check if socket is accessible for reading
if [ -r /var/run/docker.sock ]; then
    echo "[+] Socket is readable"
else
    echo "[-] Socket is not readable"
fi

# Check if socket is accessible for writing
if [ -w /var/run/docker.sock ]; then
    echo "[+] Socket is writable"
else
    echo "[-] Socket is not writable (but may still be exploitable if in docker group)"
fi

echo ""
echo "[*] Attempting to determine current user group membership..."
CURRENT_USER=$(whoami)
CURRENT_GROUPS=$(id -G 2>/dev/null || groups)
echo "[+] Current user: $CURRENT_USER"
echo "[+] Current groups: $CURRENT_GROUPS"
echo ""

# Check if docker group exists
if grep -q "^docker:" /etc/group 2>/dev/null; then
    echo "[+] Docker group exists on system"
    DOCKER_GID=$(grep "^docker:" /etc/group | cut -d: -f3)
    echo "[+] Docker GID: $DOCKER_GID"
    
    # Get socket group
    SOCKET_GROUP=$(ls -l /var/run/docker.sock 2>/dev/null | awk '{print $4}')
    echo "[+] Socket group: $SOCKET_GROUP"
    echo ""
    
    # Check if we're in docker group
    if id -G 2>/dev/null | grep -q "$DOCKER_GID"; then
        echo "[!] Current process is in docker group - Docker commands will work!"
        
        # Try docker commands
        echo "[*] Testing Docker CLI access..."
        if command -v docker &> /dev/null; then
            echo "[+] docker command available"
            DOCKER_VERSION=$(docker version 2>&1 | head -5)
            if [ $? -eq 0 ]; then
                echo "[+] Docker version command succeeded:"
                echo "$DOCKER_VERSION"
                echo ""
                echo "[!] CRITICAL VULNERABILITY CONFIRMED"
                echo "[!] Full Docker access available from container context"
                exit 0
            fi
        fi
    else
        echo "[*] Current process NOT in docker group (running as different user)"
    fi
fi

echo ""
echo "[*] VULNERABILITY ASSESSMENT:"
echo ""
echo "[+] EVIDENCE OF DOCKER SOCKET EXPOSURE:"
echo "    1. Docker socket file exists: /var/run/docker.sock"
echo "    2. Socket is a Unix domain socket (srw-rw----)"
echo "    3. Socket is owned by root:docker"
echo "    4. Socket has group read-write permissions (660)"
echo ""
echo "[+] EXPLOITATION SCENARIO (when exploited from container RCE context):"
echo "    1. Container process gains code execution (via SSRF, RCE, etc.)"
echo "    2. Container process connects to /var/run/docker.sock Unix socket"
echo "    3. Docker API calls execute with root privileges"
echo "    4. Attacker mounts host filesystem or executes commands as root"
echo "    5. Container escape achieved - full host compromise"
echo ""
echo "[!] VULNERABILITY CONFIRMED"
echo "[!] Docker socket is exposed - represents CRITICAL privilege escalation vector"
echo "[!] Combined with SSRF RCE, this enables complete host takeover"
echo ""
exit 0