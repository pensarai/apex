#!/usr/bin/env bun

/**
 * Smoke test: does the offSec agent's in-sandbox Camoufox browser path actually
 * work inside a Daytona sandbox built the way we launch Apex in production?
 *
 * Mirrors console's prod pattern (packages/cluster-services/gen-purpose/
 * Dockerfile): everything the browser needs is baked into the image at BUILD
 * time, not installed at sandbox boot. Daytona builds offsec-camoufox.Dockerfile
 * into a cached snapshot, then this drives Apex's REAL shipping browser code
 * (`createSandboxBrowserTools` -> `sandboxPlaywright.ts`):
 *   1. ensureSandboxPlaywright finds camoufox-js + playwright-core already
 *      present (baked) and skips the runtime install/fetch
 *   2. launch headless Camoufox and navigate to --target
 *   3. screenshot -> written locally so you can eyeball it
 *
 * Run:
 *   DAYTONA_API_KEY=... bun scripts/smoke-daytona-camoufox.ts --target https://example.com
 *
 * Flags: --target <url> (required), --keep (don't delete the sandbox).
 */

import path from "node:path";
import { Daytona, Image } from "@daytonaio/sdk";
import { inProcessSubagentSpawner } from "../src/core/agents/offSecAgent/subagentSpawner";
import type { UnifiedSandbox } from "../src/core/agents/offSecAgent/tools/sandbox";
import {
  createSandboxBrowserTools,
  ensureSandboxPlaywright,
} from "../src/core/agents/offSecAgent/tools/sandboxPlaywright";
import type { ToolContext } from "../src/core/agents/offSecAgent/tools/types";
import { sessions } from "../src/core/session";

function arg(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i !== -1 ? process.argv[i + 1] : undefined;
}

const target = arg("--target");
const keep = process.argv.includes("--keep");

if (!target) {
  console.error(
    "Usage: bun scripts/smoke-daytona-camoufox.ts --target <url> [--keep]",
  );
  process.exit(1);
}

const apiKey = process.env.DAYTONA_API_KEY;
if (!apiKey) {
  console.error("DAYTONA_API_KEY is required.");
  process.exit(1);
}

const sep = "─".repeat(60);
console.log(`${sep}\nDAYTONA CAMOUFOX SMOKE TEST\nTarget:  ${target}\n${sep}`);

const daytona = new Daytona({
  apiKey,
  apiUrl: "https://app.daytona.io/api",
  ...(process.env.DAYTONA_ORG_ID
    ? { organizationId: process.env.DAYTONA_ORG_ID }
    : {}),
} as ConstructorParameters<typeof Daytona>[0]);

// Build the prod-style image from the Dockerfile (browser + deps baked in).
// Daytona caches the built snapshot by content hash, so only the FIRST run pays
// the build cost; later runs boot in seconds — exactly the production model.
const dockerfile = path.resolve(import.meta.dir, "offsec-camoufox.Dockerfile");
console.log(
  "🚀 Building image from offsec-camoufox.Dockerfile + creating sandbox…",
);
console.log(
  "   (first run builds the snapshot — apt + npm + 150MB camoufox fetch; logs below)",
);
const sbx = await daytona.create(
  {
    image: Image.fromDockerfile(dockerfile),
    language: "typescript",
    resources: { cpu: 2, memory: 4, disk: 10 },
    public: false,
    networkBlockAll: false, // browser needs to reach the target
  },
  // NB: timeout is in SECONDS. Stream snapshot-build logs so the build never
  // looks like a silent hang.
  { timeout: 900, onSnapshotCreateLogs: (c) => process.stdout.write(c) },
);
console.log(`✅ Sandbox: ${sbx.id}`);

// Adapt Daytona's process API to the UnifiedSandbox shape the tools expect.
// NB: Daytona's server-side `timeout` does NOT reliably bound a stuck command
// (a hung 150MB camoufox fetch ran ~30min past its 300s timeout). We enforce a
// hard client-side deadline so a hang surfaces as a failure the caller's retry
// loop can act on, instead of blocking forever.
const unified: UnifiedSandbox = {
  type: "linux",
  async execute(command, opts) {
    const timeoutS = opts?.timeout ?? 600;
    const exec = sbx.process.executeCommand(
      command,
      opts?.cwd,
      opts?.envVars,
      timeoutS,
    );
    const guard = new Promise<never>((_, rej) =>
      setTimeout(
        () => rej(new Error(`client timeout after ${timeoutS}s`)),
        (timeoutS + 15) * 1000,
      ),
    );
    try {
      const r = await Promise.race([exec, guard]);
      const exitCode = r.exitCode ?? 0;
      return {
        stdout: r.result ?? "",
        stderr: "",
        exitCode,
        success: exitCode === 0,
      };
    } catch (e) {
      // Surface as a non-success result (not a throw) so retry loops engage.
      return {
        stdout: String(e),
        stderr: String(e),
        exitCode: 124,
        success: false,
      };
    }
  },
};

let failed = false;
try {
  // Everything (toolchain, Firefox libs, pinned camoufox-js + playwright-core,
  // and the fetched Camoufox build) is baked into the image. This call just
  // verifies it's all present in the sandbox — it should NOT install anything.
  console.log(
    "🔎 Verifying baked Camoufox install (no runtime install expected)…",
  );
  await ensureSandboxPlaywright(unified);
  console.log("✅ Camoufox present in sandbox (baked)");

  const session = await sessions.create({
    name: "daytona-camoufox-smoke",
    targets: [target],
  });
  const ctx: ToolContext = {
    subagentSpawner: inProcessSubagentSpawner,
    session,
    agentCwd: session.rootPath,
    target,
    sandbox: unified,
  };
  const tools = createSandboxBrowserTools(ctx);

  console.log(`🌐 Launching Camoufox and navigating to ${target}…`);
  // Invoke the AI-SDK tool's execute directly; cast through a minimal fn type.
  type ToolExec = (input: unknown) => Promise<unknown>;
  const nav = (await (tools.browser_navigate.execute as ToolExec)({
    url: target,
  })) as {
    success: boolean;
    title?: string;
    url?: string;
    error?: string;
  };
  if (!nav.success) throw new Error(`navigate failed: ${nav.error}`);
  console.log(
    `✅ Navigated. Page title: ${JSON.stringify(nav.title)} (${nav.url})`,
  );

  // browser_screenshot saves the PNG to the host session's evidence dir and
  // returns its path (not base64 data).
  const shot = (await (tools.browser_screenshot.execute as ToolExec)({
    filename: "smoke",
  })) as {
    success: boolean;
    path?: string;
    message?: string;
    error?: string;
  };
  if (!shot.success) throw new Error(`screenshot failed: ${shot.error}`);
  console.log(`✅ Screenshot saved: ${shot.path}`);

  console.log(`${sep}\nPASS — Camoufox runs in a Daytona sandbox.\n${sep}`);
} catch (err) {
  failed = true;
  console.error(
    `${sep}\nFAIL — ${err instanceof Error ? err.message : String(err)}\n${sep}`,
  );
} finally {
  if (keep) {
    console.log(`(--keep) sandbox left running: ${sbx.id}`);
  } else {
    console.log("🧹 Deleting sandbox…");
    await sbx.delete().catch((e) => console.error(`cleanup failed: ${e}`));
  }
}

process.exit(failed ? 1 : 0);
