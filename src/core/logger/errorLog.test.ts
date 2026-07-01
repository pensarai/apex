import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "fs";
import os from "os";
import path from "path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// `ERROR_LOG_PATH` is computed once at module load from `os.homedir()`, so we
// point HOME at a temp dir and re-import the logger fresh per test. Never touch
// the developer's real ~/.pensar/error.log.
describe("error() → ~/.pensar/error.log", () => {
  let tmpHome: string;
  let origHome: string | undefined;

  beforeEach(() => {
    origHome = process.env.HOME;
    tmpHome = mkdtempSync(path.join(os.tmpdir(), "apex-errlog-"));
    process.env.HOME = tmpHome;
    vi.resetModules();
    // Silence the structured logger's own stderr emit (the file write is separate).
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    if (origHome === undefined) delete process.env.HOME;
    else process.env.HOME = origHome;
    rmSync(tmpHome, { recursive: true, force: true });
  });

  it("appends an [ERROR] entry and creates ~/.pensar/", async () => {
    const { createLogger } = await import("./structured");
    const errLog = path.join(tmpHome, ".pensar", "error.log");

    createLogger("CORE").error("boom", new Error("kaboom"));

    expect(existsSync(errLog)).toBe(true);
    const content = readFileSync(errLog, "utf8");
    expect(content).toContain("[ERROR]");
    expect(content).toContain("kaboom");
  });

  it("persists structured fields so the file is diagnosable alone", async () => {
    const { createLogger } = await import("./structured");
    const errLog = path.join(tmpHome, ".pensar", "error.log");

    createLogger("CORE").error("request failed", new Error("boom"), {
      workspaceId: "ws_1",
      status: 502,
    });

    const content = readFileSync(errLog, "utf8");
    expect(content).toContain("ws_1");
    expect(content).toContain("502");
  });

  it("SILENT suppresses the error.log write", async () => {
    const { createLogger } = await import("./structured");
    const errLog = path.join(tmpHome, ".pensar", "error.log");
    const log = createLogger("CORE");

    log.error("first", new Error("x")); // default INFO → written
    const before = readFileSync(errLog, "utf8");

    log.setLevel("SILENT");
    log.error("second", new Error("y")); // suppressed

    expect(readFileSync(errLog, "utf8")).toBe(before);
  });

  it("prune keeps a recent JSON line that follows an expired human entry", async () => {
    const dir = path.join(tmpHome, ".pensar");
    mkdirSync(dir, { recursive: true });
    const errLog = path.join(dir, "error.log");

    const oldTs = new Date(Date.now() - 30 * 86_400_000).toISOString();
    const recentTs = new Date().toISOString();
    writeFileSync(
      errLog,
      `${oldTs} - [ERROR] expired legacy entry\n` +
        `{"ts":"${recentTs}","level":"WARN","msg":"recent structured line"}\n`,
      "utf8",
    );

    // Any write triggers the once-per-process prune.
    const { writeErrorLog } = await import("./index");
    writeErrorLog("trigger prune", "TEST");

    const content = readFileSync(errLog, "utf8");
    expect(content).toContain("recent structured line");
    expect(content).not.toContain("expired legacy entry");
  });
});
