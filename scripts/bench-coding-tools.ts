import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import type { ToolContext } from "../src/core/agents/offSecAgent/tools/types";

const { values } = parseArgs({
  args: Bun.argv.slice(2),
  options: {
    checkout: { type: "string", default: process.cwd() },
    output: { type: "string" },
    samples: { type: "string", default: "25" },
  },
  strict: true,
});
const checkout = resolve(values.checkout ?? process.cwd());
const samples = Number(values.samples);
assert(Number.isInteger(samples) && samples > 0 && samples <= 1_000);

type ToolName =
  | "createFile"
  | "updateFile"
  | "applyPatch"
  | "readFile"
  | "executeCommand";
type Result = { success: boolean; [key: string]: unknown };
type Factory = (ctx: ToolContext) => {
  execute: (
    input: Record<string, unknown>,
    options: { toolCallId: string; messages: [] },
  ) => Promise<Result>;
};
const factories = new Map<ToolName, Factory>();
for (const name of [
  "createFile",
  "updateFile",
  "applyPatch",
  "readFile",
  "executeCommand",
] as const) {
  const module = await import(
    pathToFileURL(
      join(checkout, "src/core/agents/offSecAgent/tools", `${name}.ts`),
    ).href
  );
  assert.equal(typeof module[name], "function");
  factories.set(name, module[name] as Factory);
}

interface Fixture {
  root: string;
  ctx: ToolContext;
  put(path: string, content: string): Promise<void>;
  get(path: string): Promise<string>;
  call(name: ToolName, input: Record<string, unknown>): Promise<Result>;
  calls: { name: ToolName; milliseconds: number; resultBytes: number }[];
}

async function withFixture<T>(
  run: (fixture: Fixture) => Promise<T>,
): Promise<T> {
  const root = await mkdtemp(join(tmpdir(), "apex-coding-bench-"));
  const ctx = {
    agentCwd: root,
    session: { id: "coding-benchmark", rootPath: root },
  } as ToolContext;
  const calls: Fixture["calls"] = [];
  const fixture: Fixture = {
    root,
    ctx,
    calls,
    async put(path, content) {
      await writeFile(join(root, path), content);
    },
    get: (path) => readFile(join(root, path), "utf8"),
    async call(name, input) {
      const factory = factories.get(name);
      assert(factory, `Missing tool factory: ${name}`);
      const start = performance.now();
      const result = await factory(ctx).execute(
        { ...input, toolCallDescription: "Synthetic coding fixture" },
        { toolCallId: `benchmark-${calls.length}`, messages: [] },
      );
      calls.push({
        name,
        milliseconds: performance.now() - start,
        resultBytes: Buffer.byteLength(JSON.stringify(result)),
      });
      return result;
    },
  };
  try {
    return await run(fixture);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

const replacement = (path: string, before: string, after: string, line = 1) =>
  `--- a/${path}\n+++ b/${path}\n@@ -${line},1 +${line},1 @@\n-${before}\n+${after}\n`;
const shellQuote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
const cases: { name: string; run: (f: Fixture) => Promise<void> }[] = [
  {
    name: "create, run, inspect, repair, rerun helper lifecycle",
    async run(f) {
      const { PerCommandShell } = (await import(
        pathToFileURL(
          join(
            checkout,
            "src/core/agents/offSecAgent/tools/perCommandShell.ts",
          ),
        ).href
      )) as typeof import("../src/core/agents/offSecAgent/tools/perCommandShell");
      const shell = new PerCommandShell({ cwd: f.root });
      f.ctx.commandShell = shell;
      try {
        const created = await f.call("createFile", {
          path: "helper.js",
          content: "console.log(missingValue);\n",
        });
        assert.equal(created.success, true);
        const command = `${shellQuote(process.execPath)} helper.js`;
        const failed = await f.call("executeCommand", { command, timeout: 5 });
        assert.equal(failed.success, false);
        assert.match(String(failed.stderr), /missingValue/);
        const inspected = await f.call("readFile", { path: "helper.js" });
        assert.equal(inspected.success, true);
        assert.match(String(inspected.content), /missingValue/);
        const edited = await f.call("updateFile", {
          path: "helper.js",
          oldContent: "missingValue",
          newContent: "'verified helper output'",
        });
        assert.equal(edited.success, true);
        const rerun = await f.call("executeCommand", { command, timeout: 5 });
        assert.equal(rerun.success, true);
        assert.equal(String(rerun.stdout).trim(), "verified helper output");
      } finally {
        await shell.dispose();
      }
    },
  },
  {
    name: "unique literal replacement",
    async run(f) {
      await f.put("helper.js", "const value = 'old';\n");
      const result = await f.call("updateFile", {
        path: "helper.js",
        oldContent: "'old'",
        newContent: "'$&'",
      });
      assert.equal(result.success, true);
      assert.equal(await f.get("helper.js"), "const value = '$&';\n");
    },
  },
  {
    name: "ambiguous edit rejected without mutation",
    async run(f) {
      const original = "first=old\nsecond=old\n";
      await f.put("helper.txt", original);
      const result = await f.call("updateFile", {
        path: "helper.txt",
        oldContent: "old",
        newContent: "new",
      });
      assert.equal(result.success, false);
      assert.equal(await f.get("helper.txt"), original);
    },
  },
  {
    name: "explicit replaceAll updates every occurrence",
    async run(f) {
      await f.put("helper.txt", "old old\n");
      const result = await f.call("updateFile", {
        path: "helper.txt",
        oldContent: "old",
        newContent: "new",
        replaceAll: true,
      });
      assert.equal(result.success, true);
      assert.equal(await f.get("helper.txt"), "new new\n");
    },
  },
  {
    name: "empty search rejected without mutation",
    async run(f) {
      await f.put("helper.txt", "original\n");
      const result = await f.call("updateFile", {
        path: "helper.txt",
        oldContent: "",
        newContent: "accidental prefix",
      });
      assert.equal(result.success, false);
      assert.equal(await f.get("helper.txt"), "original\n");
    },
  },
  {
    name: "CRLF edit preserves line endings and BOM",
    async run(f) {
      await f.put("helper.txt", "\uFEFFfirst\r\nold\r\nlast\r\n");
      const result = await f.call("updateFile", {
        path: "helper.txt",
        oldContent: "first\nold",
        newContent: "first\nnew",
      });
      assert.equal(result.success, true);
      assert.equal(await f.get("helper.txt"), "\uFEFFfirst\r\nnew\r\nlast\r\n");
    },
  },
  {
    name: "concurrent exclusive creation has one winner",
    async run(f) {
      const results = await Promise.all(
        ["first", "second"].map((content) =>
          f.call("createFile", { path: "helper.txt", content }),
        ),
      );
      assert.equal(results.filter((r) => r.success).length, 1);
      assert.equal(
        await f.get("helper.txt"),
        results[0].success ? "first" : "second",
      );
    },
  },
  {
    name: "exact-position patch",
    async run(f) {
      await f.put("helper.txt", "old\n");
      const result = await f.call("applyPatch", {
        patch: replacement("helper.txt", "old", "new"),
      });
      assert.equal(result.success, true);
      assert.equal(await f.get("helper.txt"), "new\n");
    },
  },
  {
    name: "patch relocates unique context after line drift",
    async run(f) {
      await f.put("helper.txt", "inserted\nold\n");
      const result = await f.call("applyPatch", {
        patch: replacement("helper.txt", "old", "new"),
      });
      assert.equal(result.success, true);
      assert.equal(await f.get("helper.txt"), "inserted\nnew\n");
    },
  },
  {
    name: "malformed hunk counts rejected without mutation",
    async run(f) {
      await f.put("helper.txt", "old\n");
      const result = await f.call("applyPatch", {
        patch: replacement("helper.txt", "old", "new").replace(
          "-1,1 +1,1",
          "-1,3 +1,3",
        ),
      });
      assert.equal(result.success, false);
      assert.equal(await f.get("helper.txt"), "old\n");
    },
  },
  {
    name: "invalid second file leaves first file unchanged",
    async run(f) {
      await f.put("first.txt", "old\n");
      await f.put("second.txt", "different\n");
      const result = await f.call("applyPatch", {
        patch:
          replacement("first.txt", "old", "new") +
          replacement("second.txt", "old", "new"),
      });
      assert.equal(result.success, false);
      assert.equal(await f.get("first.txt"), "old\n");
      assert.equal(await f.get("second.txt"), "different\n");
    },
  },
  {
    name: "patch preserves missing final newline",
    async run(f) {
      await f.put("helper.txt", "old");
      const result = await f.call("applyPatch", {
        patch:
          "--- a/helper.txt\n+++ b/helper.txt\n@@ -1,1 +1,1 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n",
      });
      assert.equal(result.success, true);
      assert.equal(await f.get("helper.txt"), "new");
    },
  },
  {
    name: "UTF-8 byte read exposes an exact resume cursor",
    async run(f) {
      await f.put("helper.txt", "a😀z");
      const result = await f.call("readFile", {
        path: "helper.txt",
        byteOffset: 1,
        byteCount: 4,
      });
      assert.equal(result.success, true);
      assert.equal(result.content, "😀");
      assert.equal(result.stoppedAtByte, 5);
    },
  },
  {
    name: "scoped relative paths address helper workspace",
    async run(f) {
      await mkdir(join(f.root, "helpers"));
      await f.put("helper.txt", "target source");
      await f.put("helpers/helper.txt", "agent helper");
      f.ctx.fileWorkspaceRoot = join(f.root, "helpers");
      const result = await f.call("readFile", { path: "helper.txt" });
      assert.equal(result.success, true);
      assert.match(String(result.content), /agent helper/);
      assert.doesNotMatch(String(result.content), /target source/);
    },
  },
  {
    name: "scoped read refuses target path outside helpers",
    async run(f) {
      await mkdir(join(f.root, "helpers"));
      await f.put("target.txt", "target source");
      f.ctx.fileWorkspaceRoot = join(f.root, "helpers");
      const result = await f.call("readFile", {
        path: join(f.root, "target.txt"),
      });
      assert.equal(result.success, false);
      assert.doesNotMatch(String(result.content), /target source/);
    },
  },
  {
    name: "scoped read refuses symlink escape",
    async run(f) {
      await mkdir(join(f.root, "helpers"));
      await f.put("target.txt", "target source");
      await symlink(join(f.root, "target.txt"), join(f.root, "helpers/link"));
      f.ctx.fileWorkspaceRoot = join(f.root, "helpers");
      const result = await f.call("readFile", {
        path: join(f.root, "helpers/link"),
      });
      assert.equal(result.success, false);
      assert.doesNotMatch(String(result.content), /target source/);
    },
  },
  {
    name: "sandbox failure never falls back to host read",
    async run(f) {
      await f.put("helper.txt", "host-only decoy");
      let executions = 0;
      f.ctx.sandbox = {
        type: "linux",
        async execute() {
          executions++;
          throw new Error("Synthetic sandbox unavailable");
        },
      };
      const result = await f.call("readFile", { path: "helper.txt" });
      assert.equal(result.success, false);
      assert(executions > 0);
      assert.doesNotMatch(String(result.content), /host-only decoy/);
    },
  },
];

const correctness = [];
for (const test of cases) {
  const start = performance.now();
  try {
    const calls = await withFixture(async (f) => {
      await test.run(f);
      return f.calls;
    });
    correctness.push({
      name: test.name,
      passed: true,
      calls,
      milliseconds: performance.now() - start,
    });
  } catch (error) {
    correctness.push({
      name: test.name,
      passed: false,
      error: error instanceof Error ? error.message : String(error),
      milliseconds: performance.now() - start,
    });
  }
}

const latency = [];
const latencySource = `${Array.from({ length: 1_024 }, (_, i) =>
  i === 512 ? "old" : `const value${i} = 'unchanged';`,
).join("\n")}\n`;
for (const name of ["updateFile", "applyPatch", "readFile"] as const) {
  const measurements = await withFixture(async (f) => {
    for (let i = 0; i < samples + 3; i++) {
      await f.put("helper.txt", latencySource);
      const result = await f.call(
        name,
        name === "updateFile"
          ? { path: "helper.txt", oldContent: "old", newContent: "new" }
          : name === "applyPatch"
            ? { patch: replacement("helper.txt", "old", "new", 513) }
            : { path: "helper.txt", startLine: 510, endLine: 520 },
      );
      assert.equal(result.success, true, `${name} latency fixture failed`);
      if (name !== "readFile") {
        assert.equal(
          await f.get("helper.txt"),
          latencySource.replace("\nold\n", "\nnew\n"),
        );
      } else {
        assert.equal(
          result.content,
          latencySource
            .split("\n")
            .slice(509, 520)
            .map((line, index) => `${String(510 + index).padStart(6)}|${line}`)
            .join("\n"),
        );
      }
    }
    return f.calls.slice(3);
  });
  const sorted = measurements.map((m) => m.milliseconds).sort((a, b) => a - b);
  latency.push({
    tool: name,
    samples,
    warmup: 3,
    inputFileBytes: Buffer.byteLength(latencySource),
    operation:
      name === "readFile" ? "11-line window" : "one replacement at line 513",
    medianMs: sorted[Math.ceil(samples * 0.5) - 1],
    p95Ms: sorted[Math.ceil(samples * 0.95) - 1],
    meanResultBytes:
      measurements.reduce((sum, m) => sum + m.resultBytes, 0) / samples,
  });
}

const report = {
  schemaVersion: 1,
  recordedAt: new Date().toISOString(),
  checkout,
  commit: execFileSync("git", ["-C", checkout, "rev-parse", "HEAD"], {
    encoding: "utf8",
  }).trim(),
  dirty:
    execFileSync("git", ["-C", checkout, "status", "--porcelain"], {
      encoding: "utf8",
    }).length > 0,
  environment: {
    platform: process.platform,
    architecture: process.arch,
    bun: Bun.version,
  },
  scope:
    "Deterministic synthetic tool contracts and warm local execution latency. No model calls, network targets, cloud sandbox, or Windows runtime. Case selection targets changed contracts; pass rate is not a general agent success rate.",
  planned: cases.length,
  completed: correctness.length,
  passed: correctness.filter((r) => r.passed).length,
  correctness,
  latency,
};
const json = `${JSON.stringify(report, null, 2)}\n`;
if (values.output) await writeFile(resolve(values.output), json);
process.stdout.write(json);
