import { readdirSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";
import { PerCommandShell } from "../agents/offSecAgent/tools/perCommandShell";
import type { ToolContext } from "../agents/offSecAgent/tools/types";
import type { SessionInfo } from "../session";
import { LocalBackends } from "../tools/backends";
import type { CommandBackend } from "../tools/backends/types";
import { readTextPrefix } from "./artifacts";
import { runCommandBounded } from "./boundedProcess";
import {
  createWhiteboxCandidate,
  listWhiteboxCandidates,
  pollWhiteboxJob,
  profileCodebase,
  queryWhiteboxCatalog,
  readWhiteboxArtifact,
  readWhiteboxJobLog,
  resolvePathWithinCodebaseRoot,
  resolveSessionWhiteboxArtifactPath,
  selectScanAdaptersWithMeta,
  startWhiteboxJob,
  updateWhiteboxCandidate,
  writeWhiteboxArtifact,
} from "./index";

// Passthrough fs/promises instrumentation: counts accrue only while armed
// around a public reader call, so fixture setup and parity checks stay
// uncounted. Counts real bytes returned by FileHandle.read and whole-file
// readFile calls — never a helper's self-report.
const io = vi.hoisted(() => ({
  active: false,
  handleReadBytes: 0,
  readFileCalls: 0,
  readFileBytes: 0,
}));

vi.mock("node:fs/promises", async () => {
  const actual =
    await vi.importActual<typeof import("node:fs/promises")>(
      "node:fs/promises",
    );
  return {
    ...actual,
    open: async (...args: Parameters<typeof actual.open>) => {
      const handle = await actual.open(...args);
      if (!io.active) return handle;
      const originalRead = handle.read.bind(handle);
      handle.read = (async (...readArgs: unknown[]) => {
        const result = await originalRead(
          ...(readArgs as Parameters<typeof originalRead>),
        );
        io.handleReadBytes += result.bytesRead;
        return result;
      }) as typeof handle.read;
      return handle;
    },
    readFile: async (...args: Parameters<typeof actual.readFile>) => {
      const result = await actual.readFile(...args);
      if (io.active) {
        io.readFileCalls++;
        io.readFileBytes +=
          typeof result === "string"
            ? Buffer.byteLength(result)
            : result.byteLength;
      }
      return result;
    },
  };
});

const cleanupRoots: string[] = [];

afterAll(async () => {
  for (const root of cleanupRoots) {
    await rm(root, { recursive: true, force: true });
  }
});

async function tempDir(prefix: string): Promise<string> {
  return mkdtemp(join(tmpdir(), prefix));
}

function mockSession(rootPath: string): SessionInfo {
  return {
    id: "ses_test",
    version: "1.0.0",
    targets: [],
    time: { created: Date.now(), updated: Date.now() },
    rootPath,
    logsPath: join(rootPath, "logs"),
    findingsPath: join(rootPath, "findings"),
    scratchpadPath: join(rootPath, "scratchpad"),
    pocsPath: join(rootPath, "pocs"),
    config: {},
  };
}

async function waitForJob(
  id: string,
): Promise<ReturnType<typeof pollWhiteboxJob>> {
  for (let i = 0; i < 40; i++) {
    const record = pollWhiteboxJob(id);
    if (record && record.status !== "running") return record;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  return pollWhiteboxJob(id);
}

/** A real, disposable `command` backend rooted at `root` for `profileCodebase`. */
function commandBackendFor(root: string): {
  command: CommandBackend;
  dispose: () => void;
} {
  const shell = new PerCommandShell({ cwd: root });
  const ctx = {
    agentCwd: root,
    session: mockSession(root),
    commandShell: shell,
  } as ToolContext;
  return {
    command: LocalBackends(ctx).command,
    dispose: () => shell.dispose(),
  };
}

describe("whitebox catalog", () => {
  it("returns focused sink records without requiring the whole playbook", () => {
    const records = queryWhiteboxCatalog({
      query: "Node SSRF",
      kind: "sink",
      limit: 5,
    });

    expect(records.length).toBeGreaterThan(0);
    expect(records.every((record) => record.kind === "sink")).toBe(true);
  });
});

describe("profileCodebase", () => {
  it("detects languages, package managers, manifests, lockfiles, and entry hints", async () => {
    const root = await tempDir("apex-whitebox-profile-");
    await writeFile(
      join(root, "package.json"),
      JSON.stringify({ scripts: { build: "tsc", test: "vitest" } }),
    );
    await writeFile(join(root, "package-lock.json"), "{}");
    await mkdir(join(root, "src"), { recursive: true });
    await writeFile(join(root, "src", "routes.ts"), "app.get('/x', handler);");

    const { command, dispose } = commandBackendFor(root);
    const profile = await profileCodebase(root, command).finally(dispose);

    expect(profile.languages).toContain("typescript");
    expect(profile.packageManagers).toContain("npm");
    expect(profile.manifestFiles).toContain("package.json");
    expect(profile.lockfiles).toContain("package-lock.json");
    expect(profile.buildCommands).toContain("npm run build");
    expect(profile.testCommands).toContain("npm run test");
    expect(profile.entryPointHints).toContain("src/routes.ts");
  });
});

describe("whitebox paths", () => {
  it("rejects path escapes outside the codebase root", () => {
    expect(() =>
      resolvePathWithinCodebaseRoot("/tmp/apex-whitebox-root", "../.."),
    ).toThrow(/escapes codebase root/);
  });

  it("only allows whitebox artifact prefixes for session reads", () => {
    expect(() =>
      resolveSessionWhiteboxArtifactPath({
        sessionRootPath: "/session",
        artifactRelativePath: "findings/evil.txt",
      }),
    ).toThrow(/logs\/whitebox/);
  });
});

describe("readWhiteboxArtifact", () => {
  it("round-trips a logs/whitebox artifact", async () => {
    const root = await tempDir("apex-whitebox-artifact-");
    const session = mockSession(root);
    const ref = await writeWhiteboxArtifact({
      session,
      type: "raw-output",
      name: "unit-test",
      content: "hello-whitebox-artifact",
      description: "test",
    });
    const read = await readWhiteboxArtifact({
      session,
      path: ref.path,
    });
    expect(read.content).toContain("hello-whitebox-artifact");
    expect(read.truncated).toBe(false);
  });

  it("round-trips an artifact whose name contains '..' from a regex pattern", async () => {
    const root = await tempDir("apex-whitebox-artifact-dots-");
    const session = mockSession(root);
    const ref = await writeWhiteboxArtifact({
      session,
      type: "code-query",
      name: "rg-../../etc/passwd",
      content: "traversal-search-results",
      description: "path traversal query",
      extension: ".txt",
    });
    expect(ref.path).not.toContain("..");
    const read = await readWhiteboxArtifact({
      session,
      path: ref.path,
    });
    expect(read.content).toContain("traversal-search-results");
  });
});

const TRUNCATION_MARKER =
  "\n\n(truncated - read the artifact in smaller chunks if needed)";

async function writeFixture(
  prefix: string,
  bytes: Buffer | string,
): Promise<string> {
  const path = await mkdtemp(join(tmpdir(), prefix));
  const file = join(path, "fixture.txt");
  await writeFile(file, bytes);
  return file;
}

async function expectPrefixMatchesWholeFileRead(
  path: string,
  maxChars: number,
): Promise<void> {
  const whole = await readFile(path, "utf-8");
  const prefix = await readTextPrefix(path, maxChars);
  expect(prefix.content).toBe(whole.slice(0, maxChars));
  expect(prefix.truncated).toBe(whole.length > maxChars);
}

describe("readTextPrefix", () => {
  it("decodes a prefix that straddles chunk boundaries mid-codepoint", async () => {
    // 21,000 three-byte chars: the 16 KiB read boundary repeatedly splits
    // a CJK codepoint, exercising decoder state carried across reads.
    const path = await writeFixture(
      "apex-whitebox-prefix-cjk-",
      "漢".repeat(21_000),
    );
    await expectPrefixMatchesWholeFileRead(path, 20_000);
    await expectPrefixMatchesWholeFileRead(path, 19_999);
    await expectPrefixMatchesWholeFileRead(path, 1);
  });

  it("matches whole-file decoding for malformed UTF-8 bytes", async () => {
    const bytes = Buffer.concat([
      Buffer.from("start "),
      Buffer.from([0xff, 0xfe, 0xc0, 0x80]),
      Buffer.from("middle"),
      Buffer.from([0xe6, 0x9c]), // truncated 3-byte sequence at EOF
      Buffer.from("end"),
    ]);
    const path = await writeFixture("apex-whitebox-prefix-badutf8-", bytes);
    await expectPrefixMatchesWholeFileRead(path, 2);
    await expectPrefixMatchesWholeFileRead(path, 7);
    await expectPrefixMatchesWholeFileRead(path, 20);
  });

  it("flushes an incomplete trailing sequence exactly like readFile utf8", async () => {
    const path = await writeFixture(
      "apex-whitebox-prefix-hangbyte-",
      Buffer.concat([Buffer.from("tail"), Buffer.from([0xe6, 0x9c])]),
    );
    const prefix = await readTextPrefix(path, 100);
    const whole = await readFile(path, "utf-8");
    expect(prefix.content).toBe(whole);
    expect(prefix.content.endsWith("\uFFFD")).toBe(true);
    expect(prefix.truncated).toBe(false);
  });

  it("keeps the lone surrogate half when the limit splits an astral pair", async () => {
    const path = await writeFixture(
      "apex-whitebox-prefix-surrogate-",
      "😀".repeat(30),
    );
    await expectPrefixMatchesWholeFileRead(path, 41);
    const prefix = await readTextPrefix(path, 41);
    // 40 full pairs plus the high surrogate of pair 21 — String#slice
    // semantics, not a codepoint boundary.
    expect(prefix.content.charCodeAt(40)).toBe(0xd83d);
    expect(prefix.content.length).toBe(41);
  });

  it("returns empty content for an empty file without marking it truncated", async () => {
    const path = await writeFixture("apex-whitebox-prefix-empty-", "");
    const prefix = await readTextPrefix(path, 10);
    expect(prefix.content).toBe("");
    expect(prefix.truncated).toBe(false);
    expect(prefix.bytesRead).toBe(0);
  });

  it("rejects hostile limit parameters instead of reading unbounded", async () => {
    const path = await writeFixture("apex-whitebox-prefix-badlimit-", "abc");
    await expect(readTextPrefix(path, Infinity)).rejects.toThrow(RangeError);
    await expect(readTextPrefix(path, Number.NaN)).rejects.toThrow(RangeError);
    await expect(readTextPrefix(path, -1)).rejects.toThrow(RangeError);
    await expect(readTextPrefix(path, 2.5)).rejects.toThrow(RangeError);
    const safe = await readTextPrefix(path, 2);
    expect(safe.content).toBe("ab");
    expect(safe.truncated).toBe(true);
  });

  it("does not truncate when the file length equals the limit exactly", async () => {
    const path = await writeFixture(
      "apex-whitebox-prefix-exact-",
      "ab".repeat(25),
    );
    const prefix = await readTextPrefix(path, 50);
    expect(prefix.content).toBe("ab".repeat(25));
    expect(prefix.truncated).toBe(false);
    expect(prefix.bytesRead).toBe(50);
  });

  it.skipIf(process.platform === "win32")(
    "closes the file handle when a read fails mid-file",
    async () => {
      // Reading a directory: open() succeeds, read() fails with EISDIR, so
      // only the finally path can release the descriptor.
      const dirPath = await mkdtemp(join(tmpdir(), "apex-whitebox-dirfd-"));
      const fdsBefore = readdirSync("/dev/fd").length;
      await expect(readTextPrefix(dirPath, 10)).rejects.toThrow(/EISDIR/);
      expect(readdirSync("/dev/fd").length).toBe(fdsBefore);
    },
  );
});

describe("readWhiteboxArtifact bounded previews", () => {
  async function readArtifactCountingIo(
    session: SessionInfo,
    path: string,
  ): Promise<{
    read: Awaited<ReturnType<typeof readWhiteboxArtifact>>;
    handleReadBytes: number;
    readFileCalls: number;
    readFileBytes: number;
  }> {
    io.active = true;
    io.handleReadBytes = 0;
    io.readFileCalls = 0;
    io.readFileBytes = 0;
    try {
      const read = await readWhiteboxArtifact({ session, path });
      return {
        read,
        handleReadBytes: io.handleReadBytes,
        readFileCalls: io.readFileCalls,
        readFileBytes: io.readFileBytes,
      };
    } finally {
      io.active = false;
    }
  }

  it("consumes only 49,152 file bytes of a 32 MiB ASCII artifact for the 40k-char preview", async () => {
    const root = await tempDir("apex-whitebox-preview-32m-");
    cleanupRoots.push(root);
    const session = mockSession(root);
    const big = "a".repeat(32 * 1024 * 1024);
    const ref = await writeWhiteboxArtifact({
      session,
      type: "raw-output",
      name: "huge",
      content: big,
      description: "32 MiB fixture",
    });

    const observed = await readArtifactCountingIo(session, ref.path);

    // Resource gate first: three 16 KiB chunks of file bytes consumed, and
    // no whole-file read through the public reader.
    expect(observed.handleReadBytes + observed.readFileBytes).toBe(49_152);
    expect(observed.readFileCalls).toBe(0);

    expect(observed.read.truncated).toBe(true);
    expect(observed.read.content).toBe(
      `${"a".repeat(40_000)}${TRUNCATION_MARKER}`,
    );
    const whole = await readFile(observed.read.absolutePath, "utf-8");
    expect(whole.length).toBe(32 * 1024 * 1024);
    expect(whole).toBe(big);
  });

  it("bounds the CJK worst case to 131,072 file bytes of a 30 MB artifact", async () => {
    const root = await tempDir("apex-whitebox-preview-cjk-");
    cleanupRoots.push(root);
    const session = mockSession(root);
    // 3 UTF-8 bytes per UTF-16 unit is the worst per-unit cost, so the
    // 40,000-unit preview consumes at most
    // 16,384 * ceil(3 * 40,001 / 16,384) = 131,072 file bytes — exactly that
    // on a pure-CJK file. 30 MB decimal: 10,000,000 three-byte chars.
    const cjk = "漢".repeat(10_000_000);
    const ref = await writeWhiteboxArtifact({
      session,
      type: "raw-output",
      name: "cjk",
      content: cjk,
      description: "30 MB CJK fixture",
    });

    const observed = await readArtifactCountingIo(session, ref.path);

    expect(observed.handleReadBytes + observed.readFileBytes).toBe(131_072);
    expect(observed.readFileCalls).toBe(0);

    expect(observed.read.truncated).toBe(true);
    const whole = await readFile(observed.read.absolutePath, "utf-8");
    expect(whole.length).toBe(10_000_000);
    expect(observed.read.content).toBe(
      `${whole.slice(0, 40_000)}${TRUNCATION_MARKER}`,
    );
  });

  it("returns the full artifact when it exactly fits the inline limit", async () => {
    const root = await tempDir("apex-whitebox-preview-exact-");
    const session = mockSession(root);
    const exact = "b".repeat(40_000);
    const ref = await writeWhiteboxArtifact({
      session,
      type: "raw-output",
      name: "exact",
      content: exact,
      description: "exactly at the limit",
    });
    const read = await readWhiteboxArtifact({ session, path: ref.path });
    expect(read.content).toBe(exact);
    expect(read.truncated).toBe(false);
  });

  it("keeps the complete artifact on disk untouched after a truncated read", async () => {
    const root = await tempDir("apex-whitebox-preview-intact-");
    const session = mockSession(root);
    const big = "c".repeat(41_000);
    const ref = await writeWhiteboxArtifact({
      session,
      type: "raw-output",
      name: "intact",
      content: big,
      description: "just over the limit",
    });
    const read = await readWhiteboxArtifact({ session, path: ref.path });
    expect(read.truncated).toBe(true);

    const onDisk = await readFile(read.absolutePath, "utf-8");
    expect(onDisk.length).toBe(41_000);
    expect(onDisk).toBe(big);
  });

  it("ignores hostile size parameters — the cap is not caller-controlled", async () => {
    const root = await tempDir("apex-whitebox-preview-hostile-");
    const session = mockSession(root);
    const big = "d".repeat(50_000);
    const ref = await writeWhiteboxArtifact({
      session,
      type: "raw-output",
      name: "hostile",
      content: big,
      description: "extra size params must not widen the cap",
    });
    const read = await readWhiteboxArtifact({
      session,
      path: ref.path,
      maxChars: 100_000_000,
      limit: 100_000_000,
    } as never);
    expect(read.content).toBe(`${"d".repeat(40_000)}${TRUNCATION_MARKER}`);
    expect(read.truncated).toBe(true);
  });

  it.skipIf(process.platform === "win32")(
    "still rejects a symlink that escapes the session root",
    async () => {
      const root = await tempDir("apex-whitebox-preview-symlink-");
      const session = mockSession(root);
      const outsideRoot = await tempDir("apex-whitebox-outside-");
      const outsideFile = join(outsideRoot, "secret.txt");
      await writeFile(outsideFile, "outside-session");
      await mkdir(join(session.logsPath, "whitebox"), { recursive: true });
      const { symlink } = await import("node:fs/promises");
      await symlink(
        outsideFile,
        join(session.logsPath, "whitebox", "escape.txt"),
      );

      await expect(
        readWhiteboxArtifact({
          session,
          path: "logs/whitebox/escape.txt",
        }),
      ).rejects.toThrow(/escapes session root via symlink/);
    },
  );

  it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "propagates read errors without leaking file descriptors",
    async () => {
      // chmod 000 is still readable for root, so the EACCES fixture needs an
      // unprivileged POSIX user.
      const root = await tempDir("apex-whitebox-preview-eacces-");
      const session = mockSession(root);
      const { chmod } = await import("node:fs/promises");
      const ref = await writeWhiteboxArtifact({
        session,
        type: "raw-output",
        name: "locked",
        content: "locked-away",
        description: "unreadable fixture",
      });
      await chmod(
        join(session.logsPath, "whitebox", ref.path.split("/").pop() ?? ""),
        0o000,
      );

      const fdsBefore = readdirSync("/dev/fd").length;
      await expect(
        readWhiteboxArtifact({ session, path: ref.path }),
      ).rejects.toThrow(/EACCES/);
      expect(readdirSync("/dev/fd").length).toBe(fdsBefore);
    },
  );
});

describe("whitebox candidates", () => {
  it("keeps hypotheses separate from confirmed findings", async () => {
    const root = await tempDir("apex-whitebox-candidates-");
    const session = mockSession(root);

    const candidate = await createWhiteboxCandidate({
      session,
      title: "Potential SSRF",
      vulnerabilityClass: "ssrf",
      summary: "fetch receives user-controlled URL",
      confidence: "medium",
    });

    expect(candidate.state).toBe("hypothesis");
    await expect(
      updateWhiteboxCandidate({
        session,
        id: candidate.id,
        state: "investigating",
      }),
    ).rejects.toThrow(/artifact|sourceTrace|substantive/);

    const updated = await updateWhiteboxCandidate({
      session,
      id: candidate.id,
      state: "investigating",
      artifacts: [
        {
          path: "logs/whitebox/query.txt",
          type: "code-query",
          description: "SSRF sink query",
        },
      ],
    });

    expect(updated.state).toBe("investigating");
    expect((await listWhiteboxCandidates(session)).candidates.length).toBe(1);
  });

  it("allows investigating with substantive sourceTrace only", async () => {
    const root = await tempDir("apex-whitebox-candidates-trace-");
    const session = mockSession(root);
    const candidate = await createWhiteboxCandidate({
      session,
      title: "Trace-only",
      vulnerabilityClass: "xss",
      summary: "sink",
      confidence: "low",
    });
    const updated = await updateWhiteboxCandidate({
      session,
      id: candidate.id,
      state: "investigating",
      sourceTrace: { sink: { file: "src/render.ts", line: 12 } },
    });
    expect(updated.state).toBe("investigating");
  });

  it("rejects illegal state jumps", async () => {
    const root = await tempDir("apex-whitebox-candidates-illegal-");
    const session = mockSession(root);
    const candidate = await createWhiteboxCandidate({
      session,
      title: "Bad jump",
      vulnerabilityClass: "sqli",
      summary: "x",
      confidence: "low",
    });
    await expect(
      updateWhiteboxCandidate({
        session,
        id: candidate.id,
        state: "confirmed",
        verification: { strategy: "n/a", status: "succeeded" },
        artifacts: [
          {
            path: "logs/whitebox/x.txt",
            type: "code-query",
            description: "x",
          },
        ],
      }),
    ).rejects.toThrow(/Illegal whitebox candidate transition/);
  });

  it("requires repro_attempted and succeeded verification for confirmed", async () => {
    const root = await tempDir("apex-whitebox-candidates-confirm-");
    const session = mockSession(root);
    const candidate = await createWhiteboxCandidate({
      session,
      title: "Confirm flow",
      vulnerabilityClass: "idor",
      summary: "x",
      confidence: "high",
    });
    await updateWhiteboxCandidate({
      session,
      id: candidate.id,
      state: "investigating",
      sourceTrace: { notes: "reachable from handler" },
    });
    await updateWhiteboxCandidate({
      session,
      id: candidate.id,
      state: "repro_attempted",
      artifacts: [
        {
          path: "logs/whitebox/repro.txt",
          type: "job-log",
          description: "repro log",
        },
      ],
    });
    const confirmed = await updateWhiteboxCandidate({
      session,
      id: candidate.id,
      state: "confirmed",
      verification: { strategy: "curl PoC", status: "succeeded" },
    });
    expect(confirmed.state).toBe("confirmed");
  });

  it("returns empty list when candidates.json is corrupt", async () => {
    const root = await tempDir("apex-whitebox-candidates-badjson-");
    const session = mockSession(root);
    await mkdir(join(session.scratchpadPath, "whitebox"), { recursive: true });
    await writeFile(
      join(session.scratchpadPath, "whitebox", "candidates.json"),
      "not-json{",
    );
    expect((await listWhiteboxCandidates(session)).candidates).toEqual([]);
  });
});

describe("selectScanAdaptersWithMeta", () => {
  it("reports unknown scanner ids separately", async () => {
    const root = await tempDir("apex-whitebox-scanmeta-");
    await writeFile(join(root, "go.mod"), "module x\ngo 1.22\n");
    const { command, dispose } = commandBackendFor(root);
    const profile = await profileCodebase(root, command).finally(dispose);
    const { adapters, unknownScannerIds } = selectScanAdaptersWithMeta({
      profile,
      scannerIds: ["gosec", "definitely-not-a-scanner"],
    });
    expect(unknownScannerIds).toContain("definitely-not-a-scanner");
    expect(adapters.every((a) => a.id !== "definitely-not-a-scanner")).toBe(
      true,
    );
  });
});

describe("whitebox jobs", () => {
  it("captures bounded job output in a pollable log", async () => {
    const root = await tempDir("apex-whitebox-job-");
    const session = mockSession(root);
    const record = startWhiteboxJob({
      session,
      cwd: root,
      command: "node -e \"console.log('whitebox-job-ok')\"",
      timeoutSeconds: 5,
      name: "smoke",
    });

    const polled = await waitForJob(record.id);
    const log = readWhiteboxJobLog(record.id);

    expect(polled?.status).toBe("completed");
    expect(log.content).toContain("whitebox-job-ok");
  });

  it("preserves quoted executable and JavaScript shell metacharacters", async () => {
    const root = await tempDir("apex-whitebox-job-quotes-");
    const session = mockSession(root);
    const record = startWhiteboxJob({
      session,
      cwd: root,
      command: `"${process.execPath}" -e "process.stdout.write(['literal > output', 'literal & value', 'literal | pipe', (() => 'arrow')()].join('|'))"`,
      timeoutSeconds: 5,
      name: "quoted-command",
    });
    const polled = await waitForJob(record.id);
    const log = readWhiteboxJobLog(record.id);
    expect(polled?.status, log.content).toBe("completed");
    expect(log.content).toContain(
      "\n\nliteral > output|literal & value|literal | pipe|arrow",
    );
  });

  it("marks long-running jobs as timed out", async () => {
    const root = await tempDir("apex-whitebox-job-timeout-");
    const session = mockSession(root);
    const record = startWhiteboxJob({
      session,
      cwd: root,
      command: 'node -e "setTimeout(() => {}, 120000)"',
      timeoutSeconds: 1,
      name: "slow",
    });
    const polled = await waitForJob(record.id);
    expect(polled?.status, readWhiteboxJobLog(record.id).content).toBe(
      "timed_out",
    );
  });
});

describe("runCommandBounded without an injected backend", () => {
  it("spawns on the host: empty output stays empty and a missing binary has no exit code", async () => {
    const opts = { cwd: tmpdir(), timeoutSeconds: 5, maxTotalBytes: 1_024 };
    const empty = await runCommandBounded(undefined, ["true"], opts);
    expect(empty).toMatchObject({ stdout: "", exitCode: 0 });
    const missing = await runCommandBounded(
      undefined,
      ["apex-no-such-binary"],
      opts,
    );
    expect(missing.exitCode).toBeNull();
  });
});

describe("runCommandBounded with an injected backend", () => {
  it("preserves upstream truncation when the captured prefix fits locally", async () => {
    const command: CommandBackend = {
      async *run() {
        yield { type: "stdout", seq: 0, bytes: "prefix" };
        yield {
          type: "end",
          exitCode: 0,
          timedOut: false,
          stdoutTruncated: true,
        };
      },
    };
    const result = await runCommandBounded(command, ["scanner"], {
      cwd: "/repo",
      timeoutSeconds: 5,
      maxTotalBytes: 1024,
    });
    expect(result).toMatchObject({ stdout: "prefix", outputTruncated: true });
  });
});
