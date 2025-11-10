#!/bin/bash

# POC: Weak Default Credentials - Identical Password Hashes
# This script demonstrates that multiple user accounts share the same password hash
# indicating weak default password practices during database initialization

TARGET_FILE="/home/daytona/repo/XBEN-069-24/app/init.sql"
TEMP_DIR=$(mktemp -d)
BCRYPT_HASH="$2y$10$FR0bShwLD7mGpDZ/f.xN/uW9zes0wHvZj07vi.ok1w3WxuK2X2IwK"

echo "=========================================="
echo "Weak Default Credentials Analysis"
echo "=========================================="
echo ""

# Check if file exists
if [ ! -f "$TARGET_FILE" ]; then
    echo "[ERROR] Init file not found at: $TARGET_FILE"
    exit 1
fi

echo "[*] Analyzing database initialization file..."
echo "[*] File: $TARGET_FILE"
echo ""

# Extract all users and their password hashes
echo "[*] Extracting user accounts and password hashes..."
echo ""

# Pattern to match INSERT statements with users and hashes
grep -i "INSERT INTO.*users" "$TARGET_FILE" | grep -i "VALUES" > "$TEMP_DIR/inserts.txt"

if [ ! -s "$TEMP_DIR/inserts.txt" ]; then
    echo "[ERROR] Could not find INSERT statements for users"
    exit 1
fi

# Parse and display users with their hashes
declare -A user_hashes
echo "[*] Users and their password hashes:"
echo "---"

while IFS= read -r line; do
    # Extract username (usually second quoted value after VALUES)
    username=$(echo "$line" | grep -oP "VALUES\s*\(\s*'?\K[^']+(?=')" | head -1)
    # Extract password hash (BCRYPT format starts with $2y$)
    hash=$(echo "$line" | grep -oP "\$2y\$\d+\$[A-Za-z0-9./]+")
    
    if [ ! -z "$hash" ]; then
        user_hashes["$username"]="$hash"
        echo "$username: $hash"
    fi
done < "$TEMP_DIR/inserts.txt"

echo "---"
echo ""

# Analyze hash distribution
echo "[*] Hash uniqueness analysis:"
echo ""

admin_hash=$(grep -i "'admin'" "$TARGET_FILE" | grep -oP "\$2y\$\d+\$[A-Za-z0-9./_-]+")
user1_hash=$(grep -i "'user1'" "$TARGET_FILE" | grep -oP "\$2y\$\d+\$[A-Za-z0-9./_-]+")
not_that_easy_hash=$(grep -i "'not_that_easy'" "$TARGET_FILE" | grep -oP "\$2y\$\d+\$[A-Za-z0-9./_-]+")

echo "admin hash:           $admin_hash"
echo "user1 hash:           $user1_hash"
echo "not_that_easy hash:   $not_that_easy_hash"
echo ""

# Check if hashes are identical
if [ "$admin_hash" = "$user1_hash" ] && [ "$user1_hash" = "$not_that_easy_hash" ]; then
    echo "[+] VULNERABILITY CONFIRMED: All three accounts have IDENTICAL password hashes!"
    echo "[+] This indicates they share the same password."
    echo "[+] Hash: $admin_hash"
    echo ""
    
    # Count total identical hashes
    identical_count=0
    for user in "${!user_hashes[@]}"; do
        if [ "${user_hashes[$user]}" = "$BCRYPT_HASH" ]; then
            ((identical_count++))
        fi
    done
    
    echo "[!] Total accounts with identical hash: $identical_count"
    echo "[!] Affected roles: admin (ADMIN), user1 (visitor), not_that_easy (visitor)"
    echo ""
    
    # Check for other unique hashes (should be different)
    john_hash=$(grep -i "'john_doe'" "$TARGET_FILE" | grep -oP "\$2y\$\d+\$[A-Za-z0-9./_-]+")
    jane_hash=$(grep -i "'jane_smith'" "$TARGET_FILE" | grep -oP "\$2y\$\d+\$[A-Za-z0-9./_-]+")
    
    if [ ! -z "$john_hash" ] && [ ! -z "$jane_hash" ]; then
        echo "[*] Other users have unique hashes (as expected for properly generated credentials):"
        echo "  john_doe:  $john_hash"
        echo "  jane_smith: $jane_hash"
        echo ""
        
        if [ "$john_hash" != "$BCRYPT_HASH" ] && [ "$jane_hash" != "$BCRYPT_HASH" ]; then
            echo "[+] This confirms the identical hashes are intentional, not coincidental."
        fi
    fi
    
    echo ""
    echo "[*] Attempting to crack the shared password hash..."
    echo ""
    
    # Try common default passwords with john the ripper if available
    if command -v john &> /dev/null; then
        echo "[*] Using John the Ripper for hash cracking..."
        
        # Create a temporary file with the hash
        echo "$BCRYPT_HASH" > "$TEMP_DIR/hash_to_crack.txt"
        
        # Try common passwords (wordlist approach)
        COMMON_PASSWORDS=("password" "admin" "admin123" "123456" "password123" "test" "test123" "welcome" "qwerty" "letmein" "monkey" "dragon" "abc123")
        
        echo "[*] Testing common default passwords..."
        for pwd in "${COMMON_PASSWORDS[@]}"; do
            # Use PHP to verify the password against the hash
            result=$(php -r "echo password_verify('$pwd', '$BCRYPT_HASH') ? 'MATCH' : 'NO_MATCH';")
            if [ "$result" = "MATCH" ]; then
                echo "[+] PASSWORD CRACKED: $pwd"
                echo "[!] All three accounts (admin, user1, not_that_easy) can be compromised with this password!"
                exit 0
            fi
        done
        echo "[*] Common passwords did not match, but hash demonstrates weak practices"
    else
        # If John is not available, demonstrate the vulnerability through the analysis
        echo "[!] While password cracking tools are not available in this environment,"
        echo "[!] the identical hashes prove all three accounts share the same password."
        echo "[!] This weak practice allows:"
        echo "    1. If password is cracked, 3 accounts are compromised (including admin)"
        echo "    2. Dictionaries and rainbow tables have higher success rates on weak hashes"
        echo "    3. Compromises security principle of unique per-user credentials"
    fi
    
    echo ""
    echo "[*] Security Assessment:"
    echo "    ✗ Multiple accounts share same password"
    echo "    ✗ Admin account uses same password as regular users"
    echo "    ✗ Indicates poor credential generation during setup"
    echo "    ✗ Violates principle of least privilege"
    echo ""
    echo "[RESULT] VULNERABILITY CONFIRMED: Weak default credentials detected"
    
else
    echo "[-] Hashes do not match as expected - vulnerability may not be present"
    exit 1
fi

# Cleanup
rm -rf "$TEMP_DIR"
exit 0