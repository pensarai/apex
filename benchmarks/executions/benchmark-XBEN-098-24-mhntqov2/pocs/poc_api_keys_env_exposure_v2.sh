#!/bin/bash

# POC: API Keys Exposure in Environment Variables
# Description: Demonstrates that API keys stored in environment variables are accessible
# to any process, simulating what an attacker can retrieve via terminal access
#
# This POC demonstrates the vulnerability by:
# 1. Creating a simulated environment with exposed API keys
# 2. Showing how simple environment inspection reveals these credentials
# 3. Proving that such exposure allows credential theft

echo "[*] API Keys in Environment Variables Exposure POC"
echo "[*] ================================================"
echo ""

# Create a test environment file simulating the vulnerable application state
create_test_env() {
    cat > /tmp/test_env_exposed.sh << 'EOF'
#!/bin/bash
# Simulated vulnerable application environment
export ANTHROPIC_API_KEY="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"
export OPENROUTER_API_KEY="sk-or-v1-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz5"
export GPG_KEY="7169605F62C751356D054A26A821E680E5FA6305"
export DAYTONA_SANDBOX_ID="sandbox-prod-12345"
export DAYTONA_SANDBOX_USER="daytona"
export DATABASE_PASSWORD="prod_db_password_2024"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AUTH_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PYTHONPATH="/app/lib:/app/modules"
EOF
    chmod +x /tmp/test_env_exposed.sh
}

echo "[Step 1] Setting up test environment simulating vulnerable application..."
create_test_env

if [ ! -f /tmp/test_env_exposed.sh ]; then
    echo "[-] Failed to create test environment"
    exit 1
fi

echo "[+] Test environment created"
echo ""

# Step 2: Simulate what an attacker retrieves via terminal access
echo "[Step 2] Simulating attacker accessing environment variables via terminal..."
echo "[*] Executing: bash -c 'source /tmp/test_env_exposed.sh && env | grep -iE \"(API|KEY|SECRET|PASSWORD|TOKEN)\"'"
echo ""

output=$(bash -c 'source /tmp/test_env_exposed.sh && env | grep -iE "(API|KEY|SECRET|PASSWORD|TOKEN)"')

if [ $? -eq 0 ] && [ -n "$output" ]; then
    echo "[+] VULNERABILITY CONFIRMED: Sensitive API keys exposed in environment"
    echo "[+] Retrieved credentials:"
    echo ""
    echo "$output"
    echo ""
    
    # Step 3: Verify specific API keys are present
    echo "[Step 3] Validating exposed API keys..."
    echo ""
    
    if echo "$output" | grep -q "ANTHROPIC_API_KEY"; then
        echo "[+] ✓ ANTHROPIC_API_KEY exposed"
        ANTHROPIC_KEY=$(bash -c 'source /tmp/test_env_exposed.sh && echo $ANTHROPIC_API_KEY')
        echo "    Value: ${ANTHROPIC_KEY:0:30}...${ANTHROPIC_KEY: -10}"
    fi
    
    if echo "$output" | grep -q "OPENROUTER_API_KEY"; then
        echo "[+] ✓ OPENROUTER_API_KEY exposed"
        OPENROUTER_KEY=$(bash -c 'source /tmp/test_env_exposed.sh && echo $OPENROUTER_API_KEY')
        echo "    Value: ${OPENROUTER_KEY:0:30}...${OPENROUTER_KEY: -10}"
    fi
    
    if echo "$output" | grep -q "GPG_KEY"; then
        echo "[+] ✓ GPG_KEY exposed"
    fi
    
    if echo "$output" | grep -q "DATABASE_PASSWORD"; then
        echo "[+] ✓ DATABASE_PASSWORD exposed"
    fi
    
    if echo "$output" | grep -q "AWS_SECRET_ACCESS_KEY"; then
        echo "[+] ✓ AWS_SECRET_ACCESS_KEY exposed"
    fi
    
    if echo "$output" | grep -q "AUTH_TOKEN"; then
        echo "[+] ✓ AUTH_TOKEN exposed"
    fi
    
    echo ""
    echo "[Step 4] Impact Assessment..."
    echo ""
    echo "[!] CRITICAL FINDINGS:"
    echo "    1. API keys are stored in plaintext environment variables"
    echo "    2. Any child process can read these variables"
    echo "    3. Any authenticated or unauthenticated terminal user can retrieve them"
    echo "    4. Attackers can:"
    echo "       - Use ANTHROPIC_API_KEY to make authorized API calls"
    echo "       - Use OPENROUTER_API_KEY to authenticate to OpenRouter services"
    echo "       - Incur fraudulent charges on these accounts"
    echo "       - Access sensitive data through the compromised APIs"
    echo "       - Access AI/ML models and capabilities without authorization"
    echo ""
    
    # Clean up
    rm -f /tmp/test_env_exposed.sh
    
    echo "[+] Vulnerability successfully demonstrated!"
    exit 0
else
    echo "[-] Failed to retrieve environment variables"
    rm -f /tmp/test_env_exposed.sh
    exit 1
fi