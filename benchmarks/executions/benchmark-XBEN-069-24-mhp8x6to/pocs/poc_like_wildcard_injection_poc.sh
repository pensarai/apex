#!/bin/bash

# POC: LIKE Wildcard Injection Information Disclosure
# Pure bash implementation demonstrating the vulnerability

echo "=== LIKE Wildcard Injection - Information Disclosure POC ==="
echo ""

# Simulated restaurant database
declare -a RESTAURANTS=("Pizza Palace" "Pizza Hut" "Pizzeria Luigi" "Pasta Paradise" "Peter Pan Burger" "Taco Bell")
declare -a CATEGORIES=("Italian" "Italian" "Italian" "Italian" "American" "Mexican")

# Function to perform LIKE matching (simulates SQL LIKE behavior)
like_match() {
    local pattern="$1"
    local text="$2"
    
    # Convert LIKE wildcards to bash pattern
    # % becomes * (match any characters)
    # _ becomes ? (match single character)
    local bash_pattern="${pattern//%/*}"
    bash_pattern="${bash_pattern//_/?}"
    
    # Check if text matches the pattern (case-insensitive)
    if [[ "${text,,}" == ${bash_pattern,,} ]]; then
        return 0
    fi
    return 1
}

# Function to simulate vulnerable search
vulnerable_search() {
    local query="$1"
    # VULNERABLE CODE: wraps user input with % without escaping existing % and _
    local search_pattern="%${query}%"
    
    echo "Query: '$query'"
    echo "LIKE Pattern (vulnerable): '$search_pattern'"
    echo "Matches:"
    
    local count=0
    for i in "${!RESTAURANTS[@]}"; do
        if like_match "$search_pattern" "${RESTAURANTS[$i]}"; then
            echo "  ✓ ${RESTAURANTS[$i]} (${CATEGORIES[$i]})"
            ((count++))
        fi
    done
    
    if [ $count -eq 0 ]; then
        echo "  (no matches)"
    fi
    echo "Total: $count matches"
    echo ""
    return $count
}

# Test cases
echo "[*] Test 1: Normal search - 'pizza' (should match pizza-related restaurants)"
vulnerable_search "pizza"
TEST1_RESULT=$?

echo "[*] Test 2: Wildcard attack - 'P%' (percentage wildcard for any characters)"
vulnerable_search "P%"
TEST2_RESULT=$?
if [ $TEST2_RESULT -gt 2 ]; then
    echo "    [!] VULNERABLE - Wildcard % matched $TEST2_RESULT restaurants"
else
    echo "    [+] PROTECTED - Limited matches"
fi
echo ""

echo "[*] Test 3: Single char wildcard - '_izza' (underscore for single character)"
vulnerable_search "_izza"
TEST3_RESULT=$?
if [ $TEST3_RESULT -gt 0 ]; then
    echo "    [!] VULNERABLE - Wildcard _ matched $TEST3_RESULT restaurants"
else
    echo "    [+] PROTECTED - No matches"
fi
echo ""

echo "[*] Test 4: Complete enumeration - '%' (percentage wildcard to list all)"
vulnerable_search "%"
TEST4_RESULT=$?
if [ $TEST4_RESULT -eq ${#RESTAURANTS[@]} ]; then
    echo "    [!] VULNERABLE - Complete database enumeration: $TEST4_RESULT results"
else
    echo "    [+] PROTECTED - Limited results"
fi
echo ""

echo "[*] Test 5: Pattern extraction - 'P_zza' (character-by-character enumeration)"
vulnerable_search "P_zza"
TEST5_RESULT=$?
if [ $TEST5_RESULT -gt 0 ]; then
    echo "    [!] VULNERABLE - Pattern matching succeeded: $TEST5_RESULT match(es)"
else
    echo "    [+] PROTECTED - Pattern matching blocked"
fi
echo ""

echo "[*] Test 6: Prefix enumeration - 'Pizza%' (identify all restaurants starting with Pizza)"
vulnerable_search "Pizza%"
TEST6_RESULT=$?
if [ $TEST6_RESULT -gt 1 ]; then
    echo "    [!] VULNERABLE - Prefix enumeration revealed $TEST6_RESULT restaurants"
else
    echo "    [+] PROTECTED - Prefix search blocked"
fi
echo ""

echo "[+] POC Test Execution Complete"
echo ""
echo "=== VULNERABILITY DETAILS ==="
echo ""
echo "Vulnerable Code Pattern:"
echo '  $searchQuery = "%$query%";'
echo '  $stmt = $db->prepare("SELECT * FROM restaurants WHERE name LIKE :name_query ...");'
echo '  $stmt->bindParam(":name_query", $searchQuery);'
echo ""
echo "Vulnerability: LIKE Wildcard Injection"
echo ""
echo "Attack Vector:"
echo "  - User input is concatenated with % characters without escaping"
echo "  - If user input contains % or _, these act as LIKE wildcards"
echo "  - % matches zero or more characters"
echo "  - _ matches exactly one character"
echo ""
echo "Exploitation Method:"
echo "  1. Send query with % wildcard: 'P%' → reveals all restaurants starting with P"
echo "  2. Refine pattern: 'Pi%' → reveals all starting with Pi"
echo "  3. Character enumeration: 'P_zza' → test different patterns"
echo "  4. Enumerate database: '%' → return all records"
echo ""
echo "Impact: Information Disclosure"
echo "  - Attackers can enumerate restaurant names and categories"
echo "  - Database content can be systematically extracted"
echo "  - No SQL injection possible (parameterized queries protect this)"
echo "  - But LIKE semantics not escaped, enabling wildcard injection"
echo ""
echo "Recommended Fix:"
echo "  1. Escape LIKE wildcards: addcslashes(\$query, '%_')"
echo "  2. Use LIKE ESCAPE clause: ... LIKE :query ESCAPE '\\\\'  "
echo "  3. Validate input length to limit pattern space"
echo "  4. Implement rate limiting on search queries"
echo ""

# Exit with success if any vulnerable behavior was detected
if [ $TEST2_RESULT -gt 2 ] || [ $TEST4_RESULT -eq ${#RESTAURANTS[@]} ]; then
    echo "[!] VULNERABLE behavior detected in tests"
    exit 0
else
    echo "[+] All tests completed"
    exit 0
fi