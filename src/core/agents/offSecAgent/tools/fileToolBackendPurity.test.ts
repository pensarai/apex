import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { applyPatch } from "./applyPatch";
import { createFile } from "./createFile";
import { deleteFile } from "./deleteFile";
import { gitDiff } from "./gitDiff";
import { gitStatus } from "./gitStatus";
import { globFiles } from "./glob";
import { grep } from "./grep";
import { listFiles } from "./listFiles";
import { readFile } from "./readFile";
import type { ToolContext } from "./types";
import { updateFile } from "./updateFile";

const HERE = dirname(fileURLToPath(import.meta.url));

/**
 * The ten file tools migrated onto `FsBackend` (design §3.2, §9 A2). Each
 * factory + its source filename, so the same table drives both the
 * whole-file I/O-purity check and the per-tool `execute`-closure check.
 */
const FILE_TOOLS = [
  { name: "read_file", file: "readFile.ts", factory: readFile },
  { name: "list_files", file: "listFiles.ts", factory: listFiles },
  { name: "grep", file: "grep.ts", factory: grep },
  { name: "glob", file: "glob.ts", factory: globFiles },
  { name: "create_file", file: "createFile.ts", factory: createFile },
  { name: "update_file", file: "updateFile.ts", factory: updateFile },
  { name: "delete_file", file: "deleteFile.ts", factory: deleteFile },
  { name: "apply_patch", file: "applyPatch.ts", factory: applyPatch },
  { name: "git_status", file: "gitStatus.ts", factory: gitStatus },
  { name: "git_diff", file: "gitDiff.ts", factory: gitDiff },
] as const;

function makeCtx(): ToolContext {
  return {
    agentCwd: "/tmp/apex-purity",
    session: { id: "ses_test", rootPath: "/tmp/apex-purity" },
  } as ToolContext;
}

// Forbidden per design §3.2: a tool is describe + validate + call backend.
// None of these ten files may reach `node:fs`/`node:child_process` directly,
// spawn a process, or do a base64 sandbox echo-write — the backend owns all
// of that now.
const FORBIDDEN_FILE_PATTERNS: RegExp[] = [
  /from ["']node:fs/,
  /from ["']node:child_process/,
  /\bspawn\(/,
  /base64/i,
];

describe("file tools call the backend, not the filesystem directly", () => {
  for (const { name, file } of FILE_TOOLS) {
    it(`${name} (${file}) contains no direct fs/child_process/base64 I/O`, () => {
      const source = readFileSync(join(HERE, file), "utf-8");
      for (const pattern of FORBIDDEN_FILE_PATTERNS) {
        expect(
          pattern.test(source),
          `${file} matched forbidden pattern ${pattern}`,
        ).toBe(false);
      }
      expect(source).toContain("resolveBackends(");
    });
  }

  for (const { name, factory } of FILE_TOOLS) {
    it(`${name} tool's execute closure contains no ctx.sandbox branch`, () => {
      const tool = factory(makeCtx());
      const executeSource = tool.execute?.toString() ?? "";
      expect(executeSource).not.toMatch(/ctx\.sandbox/);
      expect(executeSource).not.toMatch(/\bspawn\(/);
      expect(executeSource).toMatch(/resolveBackends|fs\.\w+\(/);
    });
  }
});
