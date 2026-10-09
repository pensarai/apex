import { createHash, randomBytes } from "node:crypto";
import {
  chmod,
  mkdir,
  mkdtemp,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SessionInfo } from "../session";
import {
  collectSessionEvidence,
  type EvidenceReference,
  inspectSessionEvidence,
} from "./runEvidence";

const vanish = vi.hoisted(() => ({
  afterReaddir: null as (() => Promise<void>) | null,
}));

// Lets one test delete a directory between the parent readdir and the walk.
vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    readdir: async (...args: unknown[]): Promise<unknown> => {
      const entries = await (
        actual.readdir as (...a: unknown[]) => Promise<unknown>
      )(...args);
      if (vanish.afterReaddir) {
        const trigger = vanish.afterReaddir;
        vanish.afterReaddir = null;
        await trigger();
      }
      return entries;
    },
  };
});

const tempPaths: string[] = [];

async function freshRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "run-evidence-"));
  tempPaths.push(root);
  return root;
}

function sessionAt(root: string): SessionInfo {
  return {
    id: "ses_evidence",
    version: "1",
    targets: [],
    time: { created: 0, updated: 0 },
    rootPath: root,
    logsPath: join(root, "logs"),
    findingsPath: join(root, "findings"),
    scratchpadPath: join(root, "scratchpad"),
    pocsPath: join(root, "pocs"),
  };
}

const sha256 = (content: string | Buffer): string =>
  createHash("sha256").update(content).digest("hex");

afterEach(async () => {
  vanish.afterReaddir = null;
  await Promise.all(
    tempPaths.splice(0).map((p) => rm(p, { recursive: true, force: true })),
  );
});

async function writeSessionLayout(root: string): Promise<void> {
  for (const dir of [
    "findings",
    "informational",
    "pocs",
    "tasks",
    "tool-results",
    "scratchpad",
    "logs",
    "logs/tool-output",
    "subagents",
  ]) {
    await mkdir(join(root, dir));
  }
  await writeFile(join(root, "findings", "f-1.json"), "finding body");
  await writeFile(join(root, "informational", "note-1.md"), "note body");
  await writeFile(join(root, "pocs", "poc-1.py"), "print('pwned')");
  await writeFile(join(root, "tasks", "task-1.json"), '{"done": false}');
  await writeFile(join(root, "tool-results", "spill-1.txt"), "spill body");
  await writeFile(
    join(root, "logs", "tool-output", "retained-1.txt"),
    "retained command output",
  );
  await writeFile(join(root, "plan.md"), "# plan");
  // Non-evidence session files must never be referenced.
  await writeFile(join(root, "messages.json"), "[]");
  await writeFile(join(root, "trace.jsonl"), "{}");
  await writeFile(join(root, "session.json"), "{}");
  await writeFile(join(root, "README.md"), "session");
  await writeFile(join(root, "scratchpad", "wip.txt"), "scratch");
  await writeFile(join(root, "logs", "run.log"), "log");
  await writeFile(join(root, "subagents", "child.json"), "{}");
}

describe("collectSessionEvidence", () => {
  it("references exactly the known evidence locations", async () => {
    const root = await freshRoot();
    await writeSessionLayout(root);
    const session = sessionAt(root);

    const refs = await collectSessionEvidence(session);

    expect(refs.map((r) => r.path)).toEqual([
      "findings/f-1.json",
      "informational/note-1.md",
      "logs/tool-output/retained-1.txt",
      "plan.md",
      "pocs/poc-1.py",
      "tasks/task-1.json",
      "tool-results/spill-1.txt",
    ]);
    for (const ref of refs) {
      const content =
        ref.path === "findings/f-1.json"
          ? "finding body"
          : ref.path === "informational/note-1.md"
            ? "note body"
            : ref.path === "logs/tool-output/retained-1.txt"
              ? "retained command output"
              : ref.path === "plan.md"
                ? "# plan"
                : ref.path === "pocs/poc-1.py"
                  ? "print('pwned')"
                  : ref.path === "tasks/task-1.json"
                    ? '{"done": false}'
                    : "spill body";
      expect(ref.sha256).toBe(sha256(content));
      expect(ref.bytes).toBe(Buffer.byteLength(content));
    }
  });

  it("checks retained tool output for modification and deletion", async () => {
    const root = await freshRoot();
    await mkdir(join(root, "logs", "tool-output"), { recursive: true });
    const retained = join(root, "logs", "tool-output", "retained-1.txt");
    await writeFile(retained, "retained command output");
    const session = sessionAt(root);

    const [ref] = await collectSessionEvidence(session);
    expect(ref?.path).toBe("logs/tool-output/retained-1.txt");

    await writeFile(retained, "retained command output tampered");
    const [modified] = await inspectSessionEvidence(session, [ref]);
    expect(modified).toMatchObject({
      status: "modified",
      sha256: sha256("retained command output tampered"),
      bytes: Buffer.byteLength("retained command output tampered"),
    });

    await unlink(retained);
    const [missing] = await inspectSessionEvidence(session, [ref]);
    expect(missing.status).toBe("missing");
  });

  it("returns no references when every evidence location is absent", async () => {
    const root = await freshRoot();
    expect(await collectSessionEvidence(sessionAt(root))).toEqual([]);
  });

  it("follows subdirectories inside known locations", async () => {
    const root = await freshRoot();
    await mkdir(join(root, "findings", "group-a"), { recursive: true });
    await writeFile(join(root, "findings", "group-a", "f-2.json"), "nested");
    const refs = await collectSessionEvidence(sessionAt(root));
    expect(refs.map((r) => r.path)).toEqual(["findings/group-a/f-2.json"]);
    expect(refs[0].sha256).toBe(sha256("nested"));
  });

  it("follows in-root symlinks to the referenced content", async () => {
    const root = await freshRoot();
    await mkdir(join(root, "pocs"));
    await mkdir(join(root, "findings"));
    await writeFile(join(root, "pocs", "poc-1.py"), "print('pwned')");
    await symlink("../pocs/poc-1.py", join(root, "findings", "latest.py"));
    const refs = await collectSessionEvidence(sessionAt(root));
    expect(refs.map((r) => r.path)).toEqual([
      "findings/latest.py",
      "pocs/poc-1.py",
    ]);
    expect(refs[0].sha256).toBe(sha256("print('pwned')"));
  });

  it("rejects a symlink that escapes the session root", async () => {
    const root = await freshRoot();
    const outsideRoot = await freshRoot();
    await writeFile(join(outsideRoot, "secret.txt"), "secret");
    await mkdir(join(root, "findings"));
    await symlink(
      join(outsideRoot, "secret.txt"),
      join(root, "findings", "evil.json"),
    );
    await expect(collectSessionEvidence(sessionAt(root))).rejects.toThrow(
      /escapes session root/,
    );
  });

  it("rejects a symlink loop back into a known directory", async () => {
    const root = await freshRoot();
    await mkdir(join(root, "findings"));
    await writeFile(join(root, "findings", "f-1.json"), "finding body");
    await symlink("../findings", join(root, "findings", "self"));
    const refs = await collectSessionEvidence(sessionAt(root));
    expect(refs.map((r) => r.path)).toEqual(["findings/f-1.json"]);
  });

  it("reports an unreadable evidence file instead of dropping it", async () => {
    const root = await freshRoot();
    await mkdir(join(root, "findings"));
    const locked = join(root, "findings", "f-1.json");
    await writeFile(locked, "finding body");
    await chmod(locked, 0o000);
    try {
      await expect(collectSessionEvidence(sessionAt(root))).rejects.toThrow(
        /permission denied|EACCES/i,
      );
    } finally {
      await chmod(locked, 0o644);
    }
  });

  it("reports a broken symlink instead of dropping it", async () => {
    const root = await freshRoot();
    await mkdir(join(root, "findings"));
    await symlink("no-such-target", join(root, "findings", "dead.json"));
    await expect(collectSessionEvidence(sessionAt(root))).rejects.toThrow();
  });

  it("hashes large spill files by streaming", async () => {
    const root = await freshRoot();
    await mkdir(join(root, "tool-results"));
    const big = randomBytes(5 * 1024 * 1024);
    await writeFile(join(root, "tool-results", "big.bin"), big);
    const refs = await collectSessionEvidence(sessionAt(root));
    expect(refs[0].sha256).toBe(sha256(big));
    expect(refs[0].bytes).toBe(big.length);
  });

  it("reports a nested directory that vanishes mid-walk instead of skipping it", async () => {
    const root = await freshRoot();
    await mkdir(join(root, "findings", "nested"), { recursive: true });
    await writeFile(join(root, "findings", "nested", "f.json"), "nested");
    vanish.afterReaddir = async () => {
      await rm(join(root, "findings", "nested"), {
        recursive: true,
        force: true,
      });
    };
    await expect(collectSessionEvidence(sessionAt(root))).rejects.toThrow(
      /no such file or directory|ENOENT/i,
    );
  });
});

describe("inspectSessionEvidence", () => {
  it("distinguishes match, modified, and missing per reference", async () => {
    const root = await freshRoot();
    await mkdir(join(root, "findings"));
    await mkdir(join(root, "pocs"));
    await writeFile(join(root, "findings", "f-1.json"), "finding body");
    await writeFile(join(root, "pocs", "poc-1.py"), "print('pwned')");
    await writeFile(join(root, "plan.md"), "# plan");
    const session = sessionAt(root);
    const refs = await collectSessionEvidence(session);

    const [findingRef] = refs.filter((r) => r.path === "findings/f-1.json");
    const [pocRef] = refs.filter((r) => r.path === "pocs/poc-1.py");
    const [planRef] = refs.filter((r) => r.path === "plan.md");

    await writeFile(join(root, "pocs", "poc-1.py"), "print('pwned twice')");
    await unlink(join(root, "plan.md"));

    const checks = await inspectSessionEvidence(session, [
      findingRef,
      pocRef,
      planRef,
    ]);

    expect(checks[0]).toEqual({ status: "match", ref: findingRef });
    expect(checks[1]).toMatchObject({
      status: "modified",
      sha256: sha256("print('pwned twice')"),
      bytes: Buffer.byteLength("print('pwned twice')"),
    });
    expect(checks[2]).toEqual({ status: "missing", ref: planRef });
  });

  it("flags a size-only change as modified", async () => {
    const root = await freshRoot();
    await mkdir(join(root, "findings"));
    await writeFile(join(root, "findings", "f-1.json"), "finding body");
    const session = sessionAt(root);
    const [ref] = await collectSessionEvidence(session);
    await writeFile(join(root, "findings", "f-1.json"), "finding body!!!");
    const [check] = await inspectSessionEvidence(session, [ref]);
    expect(check.status).toBe("modified");
  });

  it("errors on a reference that escapes the root", async () => {
    const root = await freshRoot();
    const session = sessionAt(root);
    const hostile: EvidenceReference = {
      path: "../../etc/hosts",
      sha256: "0".repeat(64),
      bytes: 1,
    };
    const [check] = await inspectSessionEvidence(session, [hostile]);
    expect(check.status).toBe("error");
    expect(check).toMatchObject({
      reason: expect.stringContaining("escapes session root"),
    });
  });

  it("treats a ..-prefixed in-root path as contained", async () => {
    const root = await freshRoot();
    await writeFile(join(root, "..hidden"), "hidden but inside");
    const session = sessionAt(root);
    const ref: EvidenceReference = {
      path: "..hidden",
      sha256: sha256("hidden but inside"),
      bytes: Buffer.byteLength("hidden but inside"),
    };
    const [check] = await inspectSessionEvidence(session, [ref]);
    expect(check.status).toBe("match");
  });

  it("errors when a referenced file became a root-escaping symlink", async () => {
    const root = await freshRoot();
    const outsideRoot = await freshRoot();
    await writeFile(join(outsideRoot, "secret.txt"), "secret");
    await mkdir(join(root, "findings"));
    const target = join(root, "findings", "f-1.json");
    await writeFile(target, "finding body");
    const session = sessionAt(root);
    const [ref] = await collectSessionEvidence(session);
    await unlink(target);
    await symlink(join(outsideRoot, "secret.txt"), target);
    const [check] = await inspectSessionEvidence(session, [ref]);
    expect(check.status).toBe("error");
    expect(check).toMatchObject({
      reason: expect.stringContaining("escapes session root"),
    });
  });

  it("errors when a referenced file was replaced by a directory", async () => {
    const root = await freshRoot();
    await mkdir(join(root, "findings"));
    await writeFile(join(root, "findings", "f-1.json"), "finding body");
    const session = sessionAt(root);
    const [ref] = await collectSessionEvidence(session);
    await unlink(join(root, "findings", "f-1.json"));
    await mkdir(join(root, "findings", "f-1.json"));
    const [check] = await inspectSessionEvidence(session, [ref]);
    expect(check.status).toBe("error");
    expect(check).toMatchObject({
      reason: expect.stringContaining("not a regular file"),
    });
  });

  it("reports every reference missing once the session root is gone", async () => {
    const root = await freshRoot();
    await mkdir(join(root, "findings"));
    await writeFile(join(root, "findings", "f-1.json"), "finding body");
    const session = sessionAt(root);
    const refs = await collectSessionEvidence(session);
    await rm(root, { recursive: true, force: true });
    const checks = await inspectSessionEvidence(session, refs);
    expect(checks.every((c) => c.status === "missing")).toBe(true);
  });
});
