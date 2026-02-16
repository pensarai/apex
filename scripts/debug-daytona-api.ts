#!/usr/bin/env bun
/**
 * Debug script to test API connectivity from within a Daytona sandbox
 */

import { Daytona, Image } from "@daytonaio/sdk";

async function main() {
  const apiKey = process.env.DAYTONA_API_KEY;
  const anthropicKey = process.env.ANTHROPIC_API_KEY;

  if (!apiKey) {
    console.error("❌ DAYTONA_API_KEY not set");
    process.exit(1);
  }

  if (!anthropicKey) {
    console.error("❌ ANTHROPIC_API_KEY not set");
    process.exit(1);
  }

  console.log("🚀 Creating Daytona sandbox for API connectivity test...");
  console.log(`   ANTHROPIC_API_KEY: ${anthropicKey.substring(0, 10)}...`);

  const daytona = new Daytona({ apiKey });

  // Create a simple image with curl installed
  const testImage = Image.base("ubuntu:22.04").runCommands(
    "apt-get update && apt-get install -y curl dnsutils iproute2 && rm -rf /var/lib/apt/lists/*"
  );

  let sandbox;
  try {
    sandbox = await daytona.create(
      {
        image: testImage,
        envVars: {
          ANTHROPIC_API_KEY: anthropicKey,
        },
        public: true,
        networkBlockAll: false,
        resources: {
          cpu: 2,
          memory: 4,
          disk: 2,
        },
      },
      { timeout: 120000 }
    );

    console.log(`✅ Sandbox created: ${sandbox.id}`);
    console.log(`\n📡 Testing API connectivity from sandbox...\n`);

    // Test 1: Check if env var is set
    const envCheck = await sandbox.process.executeCommand(
      'if [ -n "$ANTHROPIC_API_KEY" ]; then echo "ANTHROPIC_API_KEY is set (${#ANTHROPIC_API_KEY} chars)"; else echo "NOT SET"; fi',
      undefined,
      undefined,
      10000
    );
    console.log(`1. Env var check: ${envCheck.result?.trim()}`);

    // Test 2: DNS resolution
    const dnsCheck = await sandbox.process.executeCommand(
      "nslookup api.anthropic.com 2>&1 | head -10 || echo 'nslookup not available'",
      undefined,
      undefined,
      10000
    );
    console.log(`2. DNS resolution:\n${dnsCheck.result?.trim()}\n`);

    // Test 3: Basic HTTPS connectivity
    const httpsCheck = await sandbox.process.executeCommand(
      "curl -sI https://api.anthropic.com 2>&1 | head -5",
      undefined,
      undefined,
      15000
    );
    console.log(`3. HTTPS connectivity:\n${httpsCheck.result?.trim()}\n`);

    // Test 4: Actual API call
    const apiCall = await sandbox.process.executeCommand(
      `curl -s -w "\\nHTTP_CODE:%{http_code}" https://api.anthropic.com/v1/messages \
        -H "x-api-key: $ANTHROPIC_API_KEY" \
        -H "anthropic-version: 2023-06-01" \
        -H "content-type: application/json" \
        -d '{"model":"claude-haiku-4-5","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}' 2>&1`,
      undefined,
      undefined,
      30000
    );
    console.log(`4. API call result:\n${apiCall.result?.trim()}\n`);

    // Test 5: Check network interfaces
    const netCheck = await sandbox.process.executeCommand(
      "ip addr show 2>/dev/null || ifconfig 2>/dev/null || echo 'no network tools'",
      undefined,
      undefined,
      10000
    );
    console.log(`5. Network interfaces:\n${netCheck.result?.substring(0, 500)}\n`);

    console.log("\n✅ Debug complete. Keeping sandbox alive for 60 seconds...");
    console.log(`   Sandbox ID: ${sandbox.id}`);

    // Keep alive for manual inspection if needed
    await new Promise((resolve) => setTimeout(resolve, 60000));

  } catch (error) {
    console.error("❌ Error:", error);
  } finally {
    if (sandbox) {
      console.log("\n🧹 Cleaning up sandbox...");
      try {
        await sandbox.delete();
        console.log("✅ Sandbox deleted");
      } catch (e) {
        console.error("Failed to delete sandbox:", e);
      }
    }
  }
}

main();
