import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { openSessionReport } from "./open-report";
import { REPORT_FILENAME_MD } from "../../core/report";

describe("openSessionReport", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "open-report-test-"));
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("returns an error with the path when the report file does not exist", async () => {
    const result = await openSessionReport(tempDir);
    expect(result).toContain("Report not found");
    expect(result).toContain(tempDir);
  });

  it("includes the full path on spawn failure", async () => {
    writeFileSync(join(tempDir, REPORT_FILENAME_MD), "# Test Report\n");

    const result = await openSessionReport(tempDir);

    if (result !== "") {
      expect(result).toContain(tempDir);
      expect(result).toContain(REPORT_FILENAME_MD);
    }
  });

  it("returns a string (never throws)", async () => {
    writeFileSync(join(tempDir, REPORT_FILENAME_MD), "# Test Report\n");
    const result = await openSessionReport(tempDir);
    expect(typeof result).toBe("string");
  });
});
