import { describe, expect, it } from "vitest";
import type { SessionInfo } from "../../../session";
import { type FindingJudgeRuntimeContext, judgeFinding } from "./index";
import type { FindingJudgeInput } from "./types";

const hasApiKeys = process.env.ANTHROPIC_API_KEY || process.env.OPENAI_API_KEY;
const describeOrSkip = hasApiKeys ? describe : describe.skip;

// Helper to create a minimal test session
function createTestSession(): SessionInfo {
  return {
    id: "test-session",
    version: "1.0.0",
    rootPath: "/tmp/test-session",
    logsPath: "/tmp/test-session/logs",
    findingsPath: "/tmp/test-session/findings",
    scratchpadPath: "/tmp/test-session/scratchpad",
    pocsPath: "/tmp/test-session/pocs",
    targets: ["https://example.com"],
    time: {
      created: Date.now(),
      updated: Date.now(),
    },
  };
}

describeOrSkip("Finding Judge - Title Accuracy", () => {
  it("should include titleAccurate and suggestedTitle fields in response", async () => {
    const input: FindingJudgeInput = {
      pocScript: `#!/bin/bash
set -e

# Test for rate limiting on OTP endpoint
TARGET="https://example.com/api/otp/verify"

echo "Testing rate limiting..."
for i in {1..100}; do
  curl -s -X POST "$TARGET" \\
    -H "Content-Type: application/json" \\
    -d '{"otp": "000000"}' \\
    -w "Status: %{http_code}\\n" >> /tmp/rate_limit_test.log
done

# Check if any 429 responses
if grep -q "Status: 429" /tmp/rate_limit_test.log; then
  echo "Rate limiting detected"
  exit 1
else
  echo "No rate limiting - sent 100 requests without 429 response"
  exit 0
fi
`,
      pocType: "bash",
      pocOutput: {
        stdout:
          "Testing rate limiting...\nNo rate limiting - sent 100 requests without 429 response",
        stderr: "",
        exitCode: 0,
      },
      claim: {
        title:
          "Missing Rate Limiting on OTP Verification Endpoint Enables Password Reset Takeover",
        description:
          "The OTP verification endpoint does not implement rate limiting, allowing unlimited verification attempts.",
        impact:
          "An attacker could brute-force OTP codes and take over user accounts through password reset.",
        evidence:
          "Sent 100 POST requests to /api/otp/verify without receiving any 429 rate limit responses.",
        endpoint: "https://example.com/api/otp/verify",
        vulnerabilityClass: "missing-rate-limiting",
      },
    };

    const ctx: FindingJudgeRuntimeContext = {
      model: "claude-3-haiku-20240307",
      session: createTestSession(),
      target: "https://example.com",
    };

    const result = await judgeFinding(input, ctx);

    // Log result for debugging
    console.log("\n=== Test: Password Reset Takeover ===");
    console.log("Title accurate:", result.titleAccurate);
    console.log("Suggested title:", result.suggestedTitle);
    console.log("Valid:", result.valid);
    console.log("FindingType:", result.findingType);
    console.log(
      "Reasoning (first 200 chars):",
      result.reasoning.substring(0, 200),
    );

    // Verify that title accuracy fields are properly populated
    expect(result.titleAccurate).toBeDefined();
    expect(typeof result.titleAccurate).toBe("boolean");

    // If the judge flags the title as inaccurate, verify suggested title is provided
    if (!result.titleAccurate) {
      expect(result.suggestedTitle).toBeDefined();
      expect(typeof result.suggestedTitle).toBe("string");
      expect(result.suggestedTitle).not.toContain("Takeover");
    }

    // Verify all new verification fields are present
    expect(result.verificationSteps).toBeDefined();
    expect(Array.isArray(result.verificationSteps)).toBe(true);
    expect(result.toolEvidence).toBeDefined();
    expect(Array.isArray(result.toolEvidence)).toBe(true);
    expect(typeof result.reproducedPoc).toBe("boolean");
    expect(typeof result.webResearchUsed).toBe("boolean");
    expect(result.limitations).toBeDefined();
    expect(Array.isArray(result.limitations)).toBe(true);
  }, 120000);

  it("should accept accurate title when POC demonstrates actual exploit", async () => {
    const input: FindingJudgeInput = {
      pocScript: `#!/bin/bash
set -e

# SQL injection test
TARGET="https://example.com/api/users"

echo "Testing SQL injection..."
RESPONSE=$(curl -s "$TARGET?id=1' OR '1'='1" -H "Accept: application/json")

# Check if we got more than one user back (indicating SQL injection)
if echo "$RESPONSE" | jq length | grep -q "^[2-9]"; then
  echo "SQL Injection confirmed - retrieved multiple users:"
  echo "$RESPONSE" | jq .
  exit 0
else
  echo "No SQL injection detected"
  exit 1
fi
`,
      pocType: "bash",
      pocOutput: {
        stdout: `Testing SQL injection...
SQL Injection confirmed - retrieved multiple users:
[
  {"id": 1, "name": "Admin", "email": "admin@example.com"},
  {"id": 2, "name": "User", "email": "user@example.com"}
]`,
        stderr: "",
        exitCode: 0,
      },
      claim: {
        title: "SQL Injection in User Lookup Endpoint",
        description:
          "The /api/users endpoint is vulnerable to SQL injection via the id parameter.",
        impact:
          "An attacker can retrieve sensitive user data from the database.",
        evidence:
          "Successfully injected SQL payload (1' OR '1'='1) and retrieved all users in the database.",
        endpoint: "https://example.com/api/users",
        vulnerabilityClass: "sqli",
      },
    };

    const ctx: FindingJudgeRuntimeContext = {
      model: "claude-3-haiku-20240307",
      session: createTestSession(),
      target: "https://example.com",
    };

    const result = await judgeFinding(input, ctx);

    console.log("\n=== Test: SQL Injection (should be accurate) ===");
    console.log("Title accurate:", result.titleAccurate);
    console.log("Valid:", result.valid);
    console.log(
      "Reasoning (first 200 chars):",
      result.reasoning.substring(0, 200),
    );

    expect(result.valid).toBe(true);
    expect(result.titleAccurate).toBeDefined();
    expect(typeof result.titleAccurate).toBe("boolean");
  }, 120000);
});
