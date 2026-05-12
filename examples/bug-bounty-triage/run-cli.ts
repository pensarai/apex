/**
 * examples/bug-bounty-triage/run-cli.ts
 *
 * Minimal programmatic example of the bug-bounty triage workflow.
 *
 * Reads the sample HackerOne webhook payload from `fixtures/`, runs the
 * end-to-end triage pipeline (parse → context → scope → dup → live-verify →
 * CVSS → threat-model alignment → decide → remediation draft), and writes
 * `triage.md` + `decision.json` to `out/`.
 *
 * Run:
 *   bun run examples/bug-bounty-triage/run-cli.ts \
 *     --target https://staging.acme-shop.example.com
 *
 * Requires an AI provider to be configured (PENSAR_API_KEY, ANTHROPIC_API_KEY,
 * OPENAI_API_KEY, etc.) — the same configuration the `pensar` CLI uses.
 */

import { dirname, join } from "node:path";
import { buildAuthConfig } from "../../src/core/ai";
import { config as appConfig } from "../../src/core/config";
import { AgentEventBus } from "../../src/core/eventBus";
import { runTriageWorkflow } from "../../src/core/workflows/triage";

const HERE = dirname(new URL(import.meta.url).pathname);
const FIXTURE_REPORT = join(HERE, "fixtures", "h1-webhook-report.json");
const FIXTURE_CWD = join(HERE, "fixtures");
const OUTPUT_DIR = join(HERE, "out");

async function main() {
  const argv = process.argv.slice(2);
  const target = getArg(argv, "--target") ?? "https://staging.acme-shop.example.com";

  console.log("─".repeat(60));
  console.log("Bug Bounty Triage — programmatic example");
  console.log("─".repeat(60));
  console.log(`Report:  ${FIXTURE_REPORT}`);
  console.log(`Target:  ${target}`);
  console.log(`Output:  ${OUTPUT_DIR}`);
  console.log("");

  // Surface streaming output to stdout so the example is interactive-feeling.
  const bus = new AgentEventBus();
  bus.on("text-delta", (e) => process.stdout.write(e.text));
  bus.on("tool-call-complete", (e) => console.log(`\n→ ${e.toolName}`));
  bus.on("error", (e) => console.error("Error:", e.error));

  const pensarConfig = await appConfig.get();

  const { result, triageMarkdownPath, decisionJsonPath } = await runTriageWorkflow({
    reportPath: FIXTURE_REPORT,
    target,
    // The fixtures directory contains .apex/bug-bounty/{scope,engagement,business-context}.md
    // — `runTriageWorkflow` reads them from `cwd`.
    cwd: FIXTURE_CWD,
    output: OUTPUT_DIR,
    source: "hackerone",
    eventBus: bus,
    authConfig: buildAuthConfig(pensarConfig),
  });

  console.log(`\n${"─".repeat(60)}`);
  console.log(`Decision:    ${result.decision.outcome} (${result.decision.reason})`);
  if (result.decision.suggestedHackerOneState) {
    console.log(`H1 state:    ${result.decision.suggestedHackerOneState}`);
  }
  console.log(`Triage:      ${triageMarkdownPath}`);
  console.log(`Decision:    ${decisionJsonPath}`);
  console.log("─".repeat(60));
}

function getArg(argv: string[], flag: string): string | undefined {
  const idx = argv.indexOf(flag);
  return idx !== -1 ? argv[idx + 1] : undefined;
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
