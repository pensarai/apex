import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";

const exec = promisify(execFile);
const roots: string[] = [];
const fakeTransport = `
let calls = 0;
globalThis.fetch = async (url, init) => {
  if (String(url).endsWith('/models/z-ai/glm-5.3/endpoints')) {
    return Response.json({ data: { endpoints: [{ provider_name: 'Z.AI', pricing: {
      prompt: '0.0000014', completion: '0.0000044', input_cache_read: '0.00000026'
    } }] } });
  }
  if (!String(url).endsWith('/chat/completions')) throw new Error('Unexpected network request');
  const call = ++calls;
  if (process.env.BENCH_CHECKPOINT_FAULT && call === 2) await new Promise(resolve => setTimeout(resolve, 200));
  const content = process.env.BENCH_CHECKPOINT_FAULT && call === 1
    ? process.env.OPENROUTER_API_KEY : 'The evidence marker starts with EVIDENCE_TOKEN_.';
  return Response.json({ id: 'fake-' + call, provider: 'Z.AI', model: 'z-ai/glm-5.3', created: 1, object: 'chat.completion',
    choices: [{ index: 0, message: { role: 'assistant', content }, finish_reason: 'stop' }],
    usage: { prompt_tokens: 100, completion_tokens: 5, total_tokens: 105, cost: 0.000162,
      prompt_tokens_details: { cached_tokens: 0 } }
  });
};
`;

async function runBenchmark(extra: string[] = [], fault = false) {
  const root = await mkdtemp(join(tmpdir(), "scaling-cli-test-"));
  roots.push(root);
  const baseline = join(root, "baseline");
  await symlink(
    process.cwd(),
    baseline,
    process.platform === "win32" ? "junction" : "dir",
  );
  const preload = join(root, "transport.ts");
  await writeFile(preload, fakeTransport);
  const report = join(root, "report.json");
  let exited = 0;
  try {
    await exec(
      "bun",
      [
        "--preload",
        preload,
        "scripts/bench-tool-output-scaling.ts",
        "--baseline",
        baseline,
        "--candidate",
        process.cwd(),
        "--output",
        report,
        "--live",
        "--stages",
        "1",
        "--repetitions",
        "2",
        ...extra,
      ],
      {
        cwd: process.cwd(),
        timeout: 30000,
        env: {
          ...process.env,
          OPENROUTER_API_KEY: "benchmark-test-key",
          BENCH_CHECKPOINT_FAULT: fault ? "1" : "",
        },
      },
    );
  } catch (error) {
    if (typeof (error as { code?: unknown }).code !== "number") throw error;
    exited = (error as { code: number }).code;
  }
  return {
    exited,
    text: await readFile(report, "utf8"),
    ledger: await readFile(`${report}.jsonl`, "utf8"),
  };
}

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("scaling benchmark CLI", () => {
  it("records explanations containing a bare evidence prefix without aborting", async () => {
    const result = await runBenchmark([
      "--repetitions",
      "1",
      "--start-repetition",
      "3",
      "--profile",
      "frequent",
    ]);
    const report = JSON.parse(result.text);
    expect(result.exited).toBe(0);
    expect(report.complete).toBe(true);
    expect(report.runs).toHaveLength(2);
    expect(
      report.runs.every(
        (run: { repetition: number; profile: string }) =>
          run.repetition === 3 && run.profile === "frequent",
      ),
    ).toBe(true);
    expect(
      report.runs.every(
        (run: { completedTasks: number }) => run.completedTasks === 1,
      ),
    ).toBe(true);
    expect(result.text + result.ledger).not.toContain("EVIDENCE_TOKEN_");
    expect(result.text + result.ledger).not.toContain("benchmark-test-key");
  });

  it("halts the whole experiment before paid requests when reservations exceed the budget", async () => {
    const result = await runBenchmark(["--budget-usd", "0.0001"]);
    const report = JSON.parse(result.text);
    expect(result.exited).toBe(0);
    expect(report.budgetStopped).toBe(true);
    expect(report.complete).toBe(false);
    expect(report.spent).toBe(0);
    expect(report.runs).toHaveLength(2);
    for (const run of report.runs) {
      expect(run.repetition).toBe(1);
      expect(run.profile).toBe("occasional");
      expect(run.error).toBe("BenchmarkSpendLimit");
      expect(run.wire).toEqual([]);
      expect(run.usage.billedCost).toBeNull();
    }
  });

  it("lets the sibling finish before cleanup when another run checkpoint fails", async () => {
    const result = await runBenchmark(["--repetitions", "1"], true);
    const report = JSON.parse(result.text);
    expect(result.exited).not.toBe(0);
    expect(report.runs).toHaveLength(1);
    expect(report.runs[0].completedTasks).toBe(1);
    expect(report.runs[0].error).toBeUndefined();
    expect(result.text + result.ledger).not.toContain("benchmark-test-key");
  });
});
