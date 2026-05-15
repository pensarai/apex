/**
 * Smoke tests for the bundled whitebox scanner / profile scripts.
 *
 * Verifies:
 *   1. profile.sh emits a JSON object with the expected top-level keys
 *      when pointed at a synthetic fixture repo on disk.
 *   2. Each run-<tool>.sh script gracefully reports "<tool> not installed"
 *      as structured JSON (exit 0) when the binary isn't on $PATH, so the
 *      agent can detect absence without a thrown shell error.
 *   3. The scripts honor their explicit <output_path> argument and never
 *      write into the target codebase cwd.
 */

import { execSync, spawnSync } from "child_process";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const SCRIPTS_DIR = join(__dirname);

const RECIPE_SCRIPTS = [
  "run-semgrep.sh",
  "run-gitleaks.sh",
  "run-osv-scanner.sh",
  "run-trivy-fs.sh",
  "run-bandit.sh",
  "run-gosec.sh",
  "run-cargo-audit.sh",
  "run-pip-audit.sh",
  "run-npm-audit.sh",
  "run-trufflehog.sh",
] as const;

function toolBin(scriptName: string): string {
  return scriptName.replace(/^run-/, "").replace(/\.sh$/, "");
}

function isOnPath(bin: string): boolean {
  const r = spawnSync("command", ["-v", bin], { shell: true });
  return r.status === 0;
}

describe("whitebox scripts", () => {
  let workDir: string;
  let codebase: string;
  let outDir: string;

  beforeEach(() => {
    workDir = mkdtempSync(join(tmpdir(), "wb-scripts-"));
    codebase = join(workDir, "codebase");
    outDir = join(workDir, "scratchpad", "whitebox", "scans");
    // Minimal multi-language fixture so profile.sh has something to detect.
    mkdirSync(codebase, { recursive: true });
    writeFileSync(join(codebase, "main.py"), "print('hi')\n");
    writeFileSync(join(codebase, "app.ts"), "export const x = 1;\n");
    writeFileSync(
      join(codebase, "package.json"),
      JSON.stringify({
        name: "fixture",
        scripts: { build: "tsc", test: "jest" },
      }),
    );
  });

  afterEach(() => {
    rmSync(workDir, { recursive: true, force: true });
  });

  it("profile.sh emits a JSON object with the expected top-level keys", () => {
    const out = execSync(`bash ${SCRIPTS_DIR}/profile.sh ${codebase}`, {
      encoding: "utf-8",
    });
    const parsed = JSON.parse(out);
    expect(parsed).toMatchObject({
      path: codebase,
    });
    expect(Array.isArray(parsed.languages)).toBe(true);
    expect(parsed.languages).toEqual(
      expect.arrayContaining(["python", "typescript"]),
    );
    expect(parsed.packageManagers).toEqual(expect.arrayContaining(["npm"]));
    expect(parsed.build).toBe("tsc");
    expect(parsed.test).toBe("jest");
    expect(Array.isArray(parsed.installedScanners)).toBe(true);
    expect(parsed.git).toBeDefined();
  });

  it("profile.sh handles a missing codebase path gracefully", () => {
    const missing = join(workDir, "does-not-exist");
    const r = spawnSync("bash", [`${SCRIPTS_DIR}/profile.sh`, missing], {
      encoding: "utf-8",
    });
    expect(r.status).toBe(0);
    const parsed = JSON.parse(r.stdout);
    expect(parsed.error).toMatch(/does not exist/);
    expect(parsed.path).toBe(missing);
  });

  describe.each(RECIPE_SCRIPTS)("%s", (script) => {
    const bin = toolBin(script);
    const installed = isOnPath(bin);

    it("returns structured JSON when the tool is missing", () => {
      // Run with a PATH that contains nothing — the script will fail
      // its `command -v <tool>` check and emit the "not installed"
      // JSON. We still need /bin and /usr/bin so bash itself + find /
      // grep can be invoked; we strip everything else.
      const out = join(outDir, `${bin}.json`);
      const slimPath = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"].join(":");
      const r = spawnSync(
        "/bin/bash",
        [`${SCRIPTS_DIR}/${script}`, codebase, "-", out],
        {
          encoding: "utf-8",
          env: { PATH: slimPath },
        },
      );
      // Some recipe scripts may not even reach the tool_present check
      // if a prerequisite (e.g. Cargo.lock) is missing — in that case
      // they emit their own structured "no prerequisite" JSON and
      // exit 0. Either path is acceptable as long as it's valid JSON
      // and exit 0.
      expect(r.status).toBe(0);
      const parsed = JSON.parse(r.stdout.trim());
      expect(parsed.error).toBeDefined();
    });

    if (installed) {
      // Best-effort: when the dev machine actually has the tool, verify
      // we don't pollute the codebase dir. We tolerate any exit code
      // from the scanner itself since CVE / lint hits return non-zero.
      it(`writes to the explicit output path (not the codebase)`, () => {
        const out = join(outDir, `${bin}.json`);
        const before = new Set(readdirSync(codebase));
        spawnSync("bash", [`${SCRIPTS_DIR}/${script}`, codebase, "-", out], {
          encoding: "utf-8",
          // Don't fail the test on scanner exit codes; we only care
          // about the side-effect (or lack thereof) on the codebase.
        });
        const after = new Set(readdirSync(codebase));
        expect(after).toEqual(before);
      });
    }
  });
});
