#!/usr/bin/env bun
/**
 * MCP-path smoke test — the path PRODUCTION actually uses.
 *
 * In prod, apex runs INSIDE the Daytona sandbox and drives the browser via the
 * local @playwright/mcp path (playwrightMcp.ts), because ctx.sandbox is unset
 * (see browserTools.ts: `ctx.sandbox ? createSandboxBrowserTools : createBrowserTools`).
 *
 * This mirrors that: it builds a prod-base image (Firefox libs + baked Camoufox
 * + bun, via offsec-mcp-camoufox.Dockerfile), boots a Daytona sandbox, clones &
 * installs the apex branch inside it, then runs apex's REAL createBrowserToolset
 * (MCP path) against --target. This is the path that uses @playwright/mcp@0.0.54,
 * which bundles playwright 1.58-alpha — so this is also where we find out whether
 * the `isMobile` protocol mismatch bites the MCP path.
 *
 * Requires: DAYTONA_API_KEY and a GitHub token (GH_TOKEN, or it shells out to
 * `gh auth token`) to clone the private apex repo.
 *
 *   DAYTONA_API_KEY=... bun scripts/smoke-daytona-mcp-camoufox.ts --target https://example.com
 *
 * Flags: --target <url> (required), --keep (don't delete the sandbox).
 */

import { Daytona, Image } from "@daytonaio/sdk";
import { execSync } from "child_process";
import path from "path";

const BRANCH = "enhancement/camoufox-support";

function arg(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i !== -1 ? process.argv[i + 1] : undefined;
}

const target = arg("--target");
const keep = process.argv.includes("--keep");

if (!target) {
  console.error(
    "Usage: bun scripts/smoke-daytona-mcp-camoufox.ts --target <url> [--keep]",
  );
  process.exit(1);
}

const apiKey = process.env.DAYTONA_API_KEY;
if (!apiKey) {
  console.error("DAYTONA_API_KEY is required.");
  process.exit(1);
}

// GitHub token to clone the private apex repo (env, or `gh auth token`).
let ghToken = process.env.GH_TOKEN || process.env.GITHUB_TOKEN || "";
if (!ghToken) {
  try {
    ghToken = execSync("gh auth token", { encoding: "utf-8" }).trim();
  } catch {
    /* fall through */
  }
}
if (!ghToken) {
  console.error("Need a GitHub token: set GH_TOKEN or run `gh auth login`.");
  process.exit(1);
}

const sep = "─".repeat(60);
console.log(
  `${sep}\nDAYTONA MCP-PATH CAMOUFOX SMOKE TEST\nTarget:  ${target}\n${sep}`,
);

const daytona = new Daytona({
  apiKey,
  apiUrl: "https://app.daytona.io/api",
  ...(process.env.DAYTONA_ORG_ID
    ? { organizationId: process.env.DAYTONA_ORG_ID }
    : {}),
} as ConstructorParameters<typeof Daytona>[0]);

const dockerfile = path.resolve(
  import.meta.dir,
  "offsec-mcp-camoufox.Dockerfile",
);
console.log(
  "🚀 Building image from offsec-mcp-camoufox.Dockerfile + creating sandbox…",
);
console.log(
  "   (first run builds the snapshot — apt + firefox libs + 662MB camoufox; logs below)",
);
const sbx = await daytona.create(
  {
    image: Image.fromDockerfile(dockerfile),
    language: "typescript",
    resources: { cpu: 4, memory: 8, disk: 10 },
    public: false,
    networkBlockAll: false,
  },
  { timeout: 900, onSnapshotCreateLogs: (c) => process.stdout.write(c) },
);
console.log(`✅ Sandbox: ${sbx.id}`);

// Client-side deadline — Daytona's server timeout doesn't reliably bound a
// stuck command (see the sandbox-path smoke test).
async function run(
  command: string,
  timeoutS: number,
  envVars?: Record<string, string>,
) {
  const exec = sbx.process.executeCommand(
    command,
    undefined,
    envVars,
    timeoutS,
  );
  const guard = new Promise<never>((_, rej) =>
    setTimeout(
      () => rej(new Error(`client timeout after ${timeoutS}s`)),
      (timeoutS + 15) * 1000,
    ),
  );
  const r = await Promise.race([exec, guard]);
  return { out: r.result ?? "", code: r.exitCode ?? 0 };
}

const PATHENV = 'export PATH="/root/.bun/bin:$PATH" && ';

let failed = false;
try {
  // Clone + install the apex branch inside the sandbox. Token passed via env
  // (not the command string) so it never lands in logs.
  console.log(`📥 Cloning apex@${BRANCH} + bun install (heavy; one-time)…`);
  const clone = await run(
    PATHENV +
      `git clone --depth 1 --branch ${BRANCH} ` +
      `https://x-access-token:$GH_TOKEN@github.com/pensarai/apex.git /app/apex 2>&1 && ` +
      `cd /app/apex && bun install 2>&1 | tail -3 && echo CLONE_OK`,
    600,
    { GH_TOKEN: ghToken },
  );
  if (!clone.out.includes("CLONE_OK")) {
    throw new Error(
      `clone/install failed (exit ${clone.code}):\n${clone.out.slice(-2000)}`,
    );
  }
  console.log("✅ apex cloned + installed");

  // Driver runs INSIDE /app/apex so it resolves apex's deps. No ctx.sandbox →
  // createBrowserToolset takes the MCP (@playwright/mcp + Camoufox) path.
  const driver = `
import { sessions } from "./src/core/session";
import { createBrowserToolset } from "./src/core/agents/offSecAgent/tools/browserTools";

const target = ${JSON.stringify(target)};
const session = await sessions.create({ name: "mcp-camoufox-smoke", targets: [target] });
const ctx: any = { session, agentCwd: session.rootPath, target };
const tools = createBrowserToolset(ctx);

const nav: any = await (tools.browser_navigate.execute as any)({ url: target });
if (!nav?.success) { console.log("SMOKE_FAIL:navigate:" + (nav?.error ?? "")); process.exit(1); }
console.log("SMOKE_NAV_OK:" + JSON.stringify(nav.title ?? "") + ":" + (nav.url ?? ""));

const shot: any = await (tools.browser_screenshot.execute as any)({ filename: "mcp-smoke" });
if (!shot?.success) { console.log("SMOKE_FAIL:screenshot:" + (shot?.error ?? "")); process.exit(1); }
console.log("SMOKE_SHOT_OK:" + (shot.path ?? ""));
console.log("SMOKE_PASS");
process.exit(0);
`;
  const b64 = Buffer.from(driver).toString("base64");
  await run(`echo "${b64}" | base64 -d > /app/apex/mcp-smoke-driver.ts`, 30);

  console.log(
    `🌐 Running apex MCP browser path (createBrowserToolset) against ${target}…`,
  );
  const res = await run(
    PATHENV +
      "cd /app/apex && bun mcp-smoke-driver.ts --target " +
      JSON.stringify(target) +
      " 2>&1",
    240,
  );
  process.stdout.write(res.out.endsWith("\n") ? res.out : res.out + "\n");

  if (!res.out.includes("SMOKE_PASS")) {
    throw new Error("MCP browser path did not reach SMOKE_PASS");
  }
  console.log(
    `${sep}\nPASS — Camoufox runs via the MCP path (prod path) in a Daytona sandbox.\n${sep}`,
  );
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
