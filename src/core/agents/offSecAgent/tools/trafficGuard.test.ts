import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  assertTrafficActionAllowed,
  classifyTrafficAction,
  inspectReferencedPrograms,
  TrafficPolicyError,
} from "./trafficGuard";
import type { ToolContext } from "./types";

const dirs: string[] = [];

afterEach(() => {
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

function ctx(rateLimitTestingAllowed: boolean): ToolContext {
  return {
    agentCwd: "/tmp",
    session: { config: {} } as ToolContext["session"],
    executionPolicy: {
      scope: { allowedHosts: [], strict: false },
      destructive: { allowed: false },
      traffic: {
        rateLimitTestingAllowed,
        availabilityImpactAllowed: false,
        requestsPerSecond: 50,
        burst: rateLimitTestingAllowed ? 50 : 1,
        maxConcurrency: rateLimitTestingAllowed ? 32 : 4,
      },
    },
  };
}

describe("traffic policy", () => {
  it("blocks rate tools without the bounded-rate opt-in", () => {
    expect(() =>
      assertTrafficActionAllowed(
        "wrk -t4 -c20 https://example.com",
        ctx(false),
      ),
    ).toThrow(TrafficPolicyError);
    expect(() =>
      assertTrafficActionAllowed("ghz --rps 20 target.example:443", ctx(false)),
    ).toThrow(TrafficPolicyError);
  });

  it("allows bounded rate tools only within the configured ceiling", () => {
    expect(() =>
      assertTrafficActionAllowed(
        "ffuf -rate 25 -t 10 -u https://example.com/FUZZ",
        ctx(true),
      ),
    ).not.toThrow();
    expect(
      classifyTrafficAction("ffuf -rate 500 -t 100", {
        requestsPerSecond: 50,
        maxConcurrency: 32,
      }).category,
    ).toBe("excessive-rate");
  });

  it("allows ordinary bounded concurrency without authorizing rate testing", () => {
    expect(() =>
      assertTrafficActionAllowed(
        "const concurrency = 4; await Promise.all(workers.map(() => fetch(url)))",
        ctx(false),
      ),
    ).not.toThrow();
    expect(() =>
      assertTrafficActionAllowed(
        "await Promise.all(urls.map((url) => fetch(url)))",
        ctx(false),
      ),
    ).toThrow("must declare a bounded concurrency");
  });

  it("always blocks availability-impact techniques", () => {
    expect(() =>
      assertTrafficActionAllowed("python slowloris.py", ctx(true)),
    ).toThrow("availability-impact");
  });

  it("inspects referenced Bun and uv programs before launch", () => {
    const dir = mkdtempSync(join(tmpdir(), "apex-policy-"));
    dirs.push(dir);
    writeFileSync(
      join(dir, "probe.ts"),
      "await Promise.all(urls.map((url) => fetch(url)));",
    );
    writeFileSync(join(dir, "probe.py"), "# decompression bomb\n");

    expect(inspectReferencedPrograms("bun probe.ts", dir)).toContain(
      "Promise.all",
    );
    expect(inspectReferencedPrograms("uv run probe.py", dir)).toContain(
      "decompression bomb",
    );
    expect(
      inspectReferencedPrograms("uv run --with requests probe.py", dir),
    ).toContain("decompression bomb");
    expect(inspectReferencedPrograms("bun run probe.ts", dir)).toContain(
      "Promise.all",
    );
  });
});
