import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const api = vi.hoisted(() => ({ updateEndpoint: vi.fn() }));
vi.mock("../core/api", () => api);

const originalArgv = process.argv;
const originalExitCode = process.exitCode;

beforeEach(() => {
  vi.resetModules();
  api.updateEndpoint.mockReset().mockResolvedValue({ id: "endpoint-1" });
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(process, "exit").mockImplementation(() => undefined as never);
});

afterEach(() => {
  process.argv = originalArgv;
  process.exitCode = originalExitCode;
  vi.restoreAllMocks();
});

async function updateWith(...args: string[]) {
  process.argv = ["bun", "apps.ts", "endpoint-update", "endpoint-1", ...args];
  await import("./apps");
}

describe("endpoint default scope CLI flags", () => {
  it("excludes with an optional user explanation", async () => {
    await updateWith(
      "--exclude-by-default",
      "--exclusion-reason",
      "Health probe",
    );
    expect(api.updateEndpoint).toHaveBeenCalledWith("endpoint-1", {
      excludedFromScan: true,
      exclusionReason: "Health probe",
    });
  });

  it("includes explicitly without inventing an exclusion reason", async () => {
    await updateWith("--include-by-default");
    expect(api.updateEndpoint).toHaveBeenCalledWith("endpoint-1", {
      excludedFromScan: false,
    });
  });

  it.each([
    ["--include-by-default", "--exclude-by-default"],
    ["--exclusion-reason", "Health probe"],
  ])("rejects conflicting or incomplete scope flags: %s", async (...flags) => {
    await updateWith(...flags);
    expect(api.updateEndpoint).not.toHaveBeenCalled();
    expect(console.error).toHaveBeenCalledWith(
      expect.stringContaining("Error:"),
    );
  });
});
