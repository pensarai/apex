import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { persistToolOutput, toolOutputForModel } from "./toolOutput";
import type { ToolContext } from "./types";

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    writeFileSync: vi.fn(actual.writeFileSync),
    unlinkSync: vi.fn(actual.unlinkSync),
    closeSync: vi.fn(actual.closeSync),
  };
});

const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
const roots: string[] = [];
const text = "complete captured evidence\n".repeat(4000);
const key = "stable-write-failure";

function logs() {
  const root = actual.mkdtempSync(join(tmpdir(), "apex-write-failure-"));
  roots.push(root);
  return root;
}

function filename(root: string, reference: string) {
  return join(
    root,
    "tool-output",
    `${reference.slice("tool-output:".length)}.txt`,
  );
}

function partialWrite() {
  const error = Object.assign(new Error("private write path /host/output"), {
    code: "ENOSPC",
  });
  vi.mocked(fs.writeFileSync).mockImplementationOnce((file, data, options) => {
    actual.writeFileSync(file, String(data).slice(0, 11), options);
    throw error;
  });
}

afterEach(() => {
  vi.mocked(fs.writeFileSync)
    .mockReset()
    .mockImplementation(actual.writeFileSync);
  vi.mocked(fs.unlinkSync).mockReset().mockImplementation(actual.unlinkSync);
  vi.mocked(fs.closeSync).mockReset().mockImplementation(actual.closeSync);
  for (const root of roots.splice(0))
    actual.rmSync(root, { recursive: true, force: true });
});

it("removes its handled partial write so the same deterministic output can be retried", () => {
  const expected = persistToolOutput(logs(), key, text);
  const root = logs();
  partialWrite();
  expect(() => persistToolOutput(root, key, text)).toThrow(
    "Referenced tool output is unavailable (ENOSPC)",
  );
  expect(actual.readdirSync(join(root, "tool-output"))).toEqual([]);
  expect(persistToolOutput(root, key, text)).toBe(expected);
  expect(actual.readFileSync(filename(root, expected), "utf8")).toBe(text);
  expect(actual.lstatSync(filename(root, expected)).nlink).toBe(1);
});

it("restores a model-visible reference after a failed partial projection", async () => {
  const output = { success: true, error: "", stdout: text };
  const context = (root: string) =>
    ({ session: { rootPath: root, logsPath: root } }) as ToolContext;
  const expected = await toolOutputForModel(context(logs()), key, output);
  const root = logs();
  partialWrite();
  const failed = await toolOutputForModel(context(root), key, output);
  expect(failed.type).toBe("text");
  expect(String(failed.value)).toContain("Failed to save captured result");
  expect(String(failed.value)).not.toContain("tool-output:");
  expect(await toolOutputForModel(context(root), key, output)).toEqual(
    expected,
  );
});

it.each([
  "corrupt",
  "symlink",
  "hardlink",
] as const)("never removes or replaces a pre-existing %s destination", (kind) => {
  const control = logs();
  const reference = persistToolOutput(control, key, text);
  const root = logs();
  actual.mkdirSync(join(root, "tool-output"));
  const file = filename(root, reference);
  const original = filename(control, reference);
  if (kind === "corrupt") actual.writeFileSync(file, "other evidence");
  else if (kind === "symlink") actual.symlinkSync(original, file);
  else actual.linkSync(original, file);
  const inode = actual.lstatSync(file).ino;
  expect(() => persistToolOutput(root, key, text)).toThrow("unavailable");
  expect(actual.lstatSync(file).ino).toBe(inode);
  expect(actual.readFileSync(file, "utf8")).toBe(
    kind === "corrupt" ? "other evidence" : text,
  );
  expect(actual.readFileSync(original, "utf8")).toBe(text);
  expect(fs.unlinkSync).not.toHaveBeenCalled();
});

it("does not remove a replacement inode observed before partial-write cleanup", () => {
  const root = logs();
  const reference = persistToolOutput(logs(), key, text);
  const file = filename(root, reference);
  vi.mocked(fs.writeFileSync).mockImplementationOnce(
    (target, data, options) => {
      actual.writeFileSync(target, String(data).slice(0, 11), options);
      actual.unlinkSync(file);
      actual.writeFileSync(file, "replacement evidence", { flag: "wx" });
      throw Object.assign(new Error("private path"), { code: "ENOSPC" });
    },
  );
  expect(() => persistToolOutput(root, key, text)).toThrow("ENOSPC");
  expect(actual.readFileSync(file, "utf8")).toBe("replacement evidence");
  expect(fs.unlinkSync).not.toHaveBeenCalled();
});

it("keeps strict read-only contention and lets an identical writer retry after completion", () => {
  const root = logs();
  const failures: unknown[] = [];
  vi.mocked(fs.writeFileSync).mockImplementationOnce((file, data) => {
    const fd =
      typeof file === "number" ? file : actual.openSync(file, "wx", 0o600);
    try {
      try {
        persistToolOutput(root, key, text);
      } catch (error) {
        failures.push(error);
      }
      actual.writeFileSync(fd, data);
    } finally {
      if (typeof file !== "number") actual.closeSync(fd);
    }
  });
  const reference = persistToolOutput(root, key, text);
  expect(failures).toEqual([
    expect.objectContaining({
      message: expect.stringContaining("unavailable"),
    }),
  ]);
  expect(persistToolOutput(root, key, text)).toBe(reference);
  expect(actual.readFileSync(filename(root, reference), "utf8")).toBe(text);
  expect(fs.unlinkSync).not.toHaveBeenCalled();
});

it("retains both write and cleanup errno without exposing host paths", () => {
  const root = logs();
  partialWrite();
  vi.mocked(fs.unlinkSync).mockImplementationOnce(() => {
    throw Object.assign(new Error(`cleanup failed for ${root}`), {
      code: "EACCES",
    });
  });
  let failure: unknown;
  try {
    persistToolOutput(root, key, text);
  } catch (error) {
    failure = error;
  }
  expect(failure).toBeInstanceOf(AggregateError);
  const aggregate = failure as AggregateError;
  expect(aggregate.errors.map((error: Error) => error.message)).toEqual([
    "Referenced tool output is unavailable (ENOSPC)",
    "Referenced tool output is unavailable (EACCES)",
  ]);
  expect(aggregate.message).toContain("ENOSPC");
  expect(aggregate.message).toContain("EACCES");
  expect(aggregate.message).not.toContain(root);
  expect(aggregate.errors.map(String).join(" ")).not.toContain("/host/output");
  expect(actual.readdirSync(join(root, "tool-output"))).toHaveLength(1);
});
