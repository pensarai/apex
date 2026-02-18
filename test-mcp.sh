#!/bin/bash

# MCP Server Testing Script
# Tests the Pensar Apex MCP server

echo "======================================"
echo "Pensar Apex MCP Server Testing"
echo "======================================"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test Results
test_pass() {
  echo -e "${GREEN}✓ PASS${NC}: $1"
}

test_fail() {
  echo -e "${RED}✗ FAIL${NC}: $1"
}

test_warn() {
  echo -e "${YELLOW}⚠ WARN${NC}: $1"
}

echo "Test 1: Check if Node.js is available"
if command -v node &> /dev/null; then
  test_pass "node found: $(node --version)"
else
  test_fail "node not found. Install from: https://nodejs.org"
  exit 1
fi
echo ""

echo "Test 1b: Check if npm is available"
if command -v npm &> /dev/null; then
  test_pass "npm found: $(npm --version)"
else
  test_fail "npm not found. Install from: https://nodejs.org"
  exit 1
fi
echo ""

# Set preferred runner - try tsx (ts-node alternative) first, then fallback to bun/node
RUNNER="bun"
if command -v bun &> /dev/null; then
  RUNNER="bun"
  test_pass "Will use bun as TypeScript runner"
elif command -v npx &> /dev/null; then
  RUNNER="npx tsx"
  test_pass "Will use npx tsx as TypeScript runner"
else
  test_fail "No TypeScript runner available (need bun or npx)"
  exit 1
fi
echo ""

echo "Test 2: Check if MCP dependencies are installed"
if grep -q "@modelcontextprotocol/sdk" package.json; then
  test_pass "MCP SDK found in package.json"
else
  test_fail "MCP SDK not in package.json"
  exit 1
fi
echo ""

echo "Test 3: Start MCP server in background"
$RUNNER scripts/mcp-server.ts &
MCP_PID=$!
echo "Started with PID: $MCP_PID"
sleep 3

# Check if process is running - handle npx wrapper processes
if ps -p $MCP_PID > /dev/null 2>&1 || pgrep -f "tsx scripts/mcp-server" > /dev/null 2>&1; then
  test_pass "MCP server is running (PID: $MCP_PID)"
else
  test_fail "MCP server failed to start"
  exit 1
fi
echo ""

echo "Test 4: Check pentest CLI is available"
if [ -f "scripts/pentest-cli.ts" ]; then
  test_pass "pentest-cli.ts found"
else
  test_fail "pentest-cli.ts not found"
  kill $MCP_PID 2>/dev/null || pkill -f "tsx scripts/mcp-server"
  exit 1
fi
echo ""

echo "Test 5: Check findings extractor is available"
if [ -f "scripts/findings-extractor.ts" ]; then
  test_pass "findings-extractor.ts found"
else
  test_fail "findings-extractor.ts not found"
  pkill -f "tsx scripts/mcp-server" 2>/dev/null
  exit 1
fi
echo ""

echo "Test 6: Test pentest CLI help"
HELP_OUTPUT=$($RUNNER scripts/pentest-cli.ts --help 2>&1 | head -5)
if echo "$HELP_OUTPUT" | grep -q "Pensar Pentest CLI"; then
  test_pass "pentest-cli --help works"
else
  test_fail "pentest-cli --help failed"
  echo "Output: $HELP_OUTPUT"
fi
echo ""

echo "Test 7: Cleanup - shutdown MCP server"
if kill $MCP_PID 2>/dev/null; then
  sleep 1
  if ! ps -p $MCP_PID > /dev/null 2>&1 && ! pgrep -f "tsx scripts/mcp-server" > /dev/null 2>&1; then
    test_pass "MCP server shut down cleanly"
  else
    test_warn "Had to force kill MCP server"
    pkill -f "tsx scripts/mcp-server" 2>/dev/null
    kill -9 $MCP_PID 2>/dev/null
  fi
else
  test_warn "MCP server already stopped"
  pkill -f "tsx scripts/mcp-server" 2>/dev/null
fi
echo ""

echo "======================================"
echo "All basic tests completed!"
echo "======================================"
echo ""
echo "Next steps:"
echo "1. Manual test: $RUNNER scripts/mcp-server.ts"
echo "2. In another terminal: Test CLI with: $RUNNER scripts/pentest-cli.ts --help"
echo "3. Integration test: Set up Cursor/Claude Code with MCP config"
echo ""
