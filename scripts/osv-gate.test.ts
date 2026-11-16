import { describe, expect, it, vi } from "vitest";
import {
  compareScans,
  findingsFromScan,
  invalidExceptions,
  lookupLicenses,
  type OsvScan,
  renderSummary,
  severityOf,
} from "./osv-gate";

interface Advisory {
  id: string;
  score?: string;
  aliases?: string[];
  fixed?: boolean;
}

const pkg = (name: string, version: string, advisories: Advisory[] = []) => ({
  package: { name, version, ecosystem: "npm" },
  vulnerabilities: advisories.map((a) => ({
    id: a.id,
    summary: `${a.id} summary`,
    affected: [
      {
        ranges: [
          {
            events: (a.fixed === false
              ? [{ introduced: "0" }]
              : [{ introduced: "0" }, { fixed: "9.9.9" }]) as Record<
              string,
              string
            >[],
          },
        ],
      },
    ],
  })),
  groups: advisories.map((a) => ({
    ids: [a.id],
    aliases: a.aliases ?? [],
    max_severity: a.score ?? "",
  })),
});

const scanOf = (...packages: ReturnType<typeof pkg>[]): OsvScan => ({
  results: [{ packages }],
});

describe("severityOf", () => {
  it.each([
    ["9.8", "critical"],
    ["9.0", "critical"],
    ["8.9", "high"],
    ["7.0", "high"],
    ["6.9", "medium"],
    ["4.0", "medium"],
    ["3.9", "low"],
    ["", "unscored"],
    [undefined, "unscored"],
  ])("maps %j to %s", (score, severity) => {
    expect(severityOf(score).severity).toBe(severity);
  });
});

describe("compareScans", () => {
  it("blocks a critical or high advisory the PR introduces", () => {
    const base = scanOf(pkg("left-pad", "1.0.0"));
    const head = scanOf(
      pkg("left-pad", "1.0.0"),
      pkg("evil", "2.0.0", [{ id: "GHSA-crit", score: "9.8" }]),
      pkg("meh", "1.0.0", [{ id: "GHSA-high", score: "7.5", fixed: false }]),
    );
    const result = compareScans(base, head);
    expect(result.blocking.map((f) => f.id).sort()).toEqual([
      "GHSA-crit",
      "GHSA-high",
    ]);
    expect(result.addedPackages).toEqual(["evil@2.0.0", "meh@1.0.0"]);
  });

  it("blocks malware whatever its severity", () => {
    const head = scanOf(
      pkg("typo-squat", "1.0.0", [{ id: "MAL-2026-1", score: "" }]),
    );
    const result = compareScans(scanOf(), head);
    expect(result.blocking.map((f) => f.id)).toEqual(["MAL-2026-1"]);
    expect(result.warnings).toEqual([]);
  });

  it("treats a malware alias as malware", () => {
    const head = scanOf(
      pkg("x", "1.0.0", [
        { id: "GHSA-abc", score: "5.0", aliases: ["MAL-2026-2"] },
      ]),
    );
    expect(compareScans(scanOf(), head).blocking).toHaveLength(1);
  });

  it("does not block an advisory already on that package in the base", () => {
    const base = scanOf(
      pkg("undici", "6.25.0", [{ id: "GHSA-old", score: "7.5" }]),
    );
    const head = scanOf(
      pkg("undici", "6.25.1", [{ id: "GHSA-old", score: "7.5" }]),
    );
    const result = compareScans(base, head);
    expect(result.blocking).toEqual([]);
    expect(result.existing.map((f) => f.id)).toEqual(["GHSA-old"]);
  });

  it("matches the same advisory when its group ids change between scans", () => {
    const base = scanOf(
      pkg("qs", "6.0.0", [
        { id: "CVE-2026-1", score: "7.5", aliases: ["GHSA-qs"] },
      ]),
    );
    const head = scanOf(pkg("qs", "6.0.1", [{ id: "GHSA-qs", score: "7.5" }]));
    const result = compareScans(base, head);
    expect(result.blocking).toEqual([]);
    expect(result.existing.map((f) => f.id)).toEqual(["GHSA-qs"]);
  });

  it("blocks a known advisory when it arrives on a package that did not have it", () => {
    const base = scanOf(
      pkg("a", "1.0.0", [{ id: "GHSA-shared", score: "8.0" }]),
    );
    const head = scanOf(
      pkg("a", "1.0.0", [{ id: "GHSA-shared", score: "8.0" }]),
      pkg("b", "1.0.0", [{ id: "GHSA-shared", score: "8.0" }]),
    );
    expect(compareScans(base, head).blocking.map((f) => f.pkg)).toEqual(["b"]);
  });

  it("warns on an unscored advisory and passes medium and low", () => {
    const head = scanOf(
      pkg("x", "1.0.0", [{ id: "GHSA-none" }]),
      pkg("y", "1.0.0", [{ id: "GHSA-med", score: "5.3" }]),
      pkg("z", "1.0.0", [{ id: "GHSA-low", score: "2.0" }]),
    );
    const result = compareScans(scanOf(), head);
    expect(result.blocking).toEqual([]);
    expect(result.warnings.map((f) => f.id)).toEqual(["GHSA-none"]);
    expect(result.introduced).toHaveLength(3);
  });

  it("records whether a fix exists", () => {
    const findings = findingsFromScan(
      scanOf(
        pkg("a", "1.0.0", [
          { id: "GHSA-fix", score: "8" },
          { id: "GHSA-nofix", score: "8", fixed: false },
        ]),
      ),
    );
    expect(findings.map((f) => [f.id, f.fixAvailable])).toEqual([
      ["GHSA-fix", true],
      ["GHSA-nofix", false],
    ]);
  });

  it("handles a scan with no results", () => {
    expect(compareScans({ results: null }, { results: [] }).introduced).toEqual(
      [],
    );
  });
});

describe("invalidExceptions", () => {
  it("accepts entries with an id and a reason", () => {
    expect(
      invalidExceptions([{ id: "GHSA-1", reason: "dev server only" }]),
    ).toEqual([]);
  });

  it("rejects an entry without a reason or an id", () => {
    expect(
      invalidExceptions([
        { id: "GHSA-1" },
        { id: "GHSA-2", reason: "  " },
        { reason: "why" },
      ]),
    ).toEqual([
      "GHSA-1 has no reason",
      "GHSA-2 has no reason",
      "entry 3 has no id",
    ]);
  });
});

describe("renderSummary", () => {
  it("names blocking findings, counts existing ones and lists added licenses", () => {
    const base = scanOf(
      pkg("old", "1.0.0", [{ id: "GHSA-old", score: "9.1" }]),
    );
    const head = scanOf(
      pkg("old", "1.0.0", [{ id: "GHSA-old", score: "9.1" }]),
      pkg("new", "1.0.0", [{ id: "GHSA-new", score: "7.2" }]),
    );
    const summary = renderSummary(
      compareScans(base, head),
      new Map([["new@1.0.0", "MIT"]]),
      [{ path: "prototypes/x/bun.lock", findings: [] }],
    );
    expect(summary).toContain(
      "**Blocked:** this PR introduces 1 critical, high or malware advisories",
    );
    expect(summary).toContain(
      "| high (7.2) | `new@1.0.0` | GHSA-new | yes | GHSA-new summary |",
    );
    expect(summary).toContain("Not blocking: 1 critical.");
    expect(summary).toContain("Not gated, `prototypes/x/bun.lock`: none.");
    expect(summary).toContain("| `new@1.0.0` | MIT |");
  });

  it("says nothing was introduced when the PR is clean", () => {
    const summary = renderSummary(
      compareScans(scanOf(), scanOf()),
      new Map(),
      [],
    );
    expect(summary).toContain(
      "No critical, high or malware advisories introduced",
    );
  });
});

describe("lookupLicenses", () => {
  const respond = (body: unknown, status = 200) =>
    Promise.resolve(new Response(JSON.stringify(body), { status }));

  it("reads string and object licenses from the registry, scoped names included", async () => {
    const fetcher = vi.fn((url: string) =>
      url.includes("%40scope%2fpkg") || url.includes("@scope%2fpkg")
        ? respond({ license: { type: "Apache-2.0" } })
        : respond({ license: "MIT" }),
    );
    const licenses = await lookupLicenses(
      ["plain@1.0.0", "@scope/pkg@2.0.0"],
      fetcher as unknown as typeof fetch,
    );
    expect(licenses.get("plain@1.0.0")).toBe("MIT");
    expect(licenses.get("@scope/pkg@2.0.0")).toBe("Apache-2.0");
    expect(fetcher).toHaveBeenCalledWith(
      "https://registry.npmjs.org/@scope%2fpkg/2.0.0",
      expect.anything(),
    );
  });

  it("reports a missing license and registry failures without throwing", async () => {
    const fetcher = vi.fn((url: string) => {
      if (url.includes("down")) return Promise.reject(new Error("ECONNRESET"));
      if (url.includes("gone")) return respond({}, 404);
      return respond({});
    });
    const licenses = await lookupLicenses(
      ["bare@1.0.0", "gone@1.0.0", "down@1.0.0"],
      fetcher as unknown as typeof fetch,
    );
    expect(licenses.get("bare@1.0.0")).toBe("none declared");
    expect(licenses.get("gone@1.0.0")).toBe("unknown (registry 404)");
    expect(licenses.get("down@1.0.0")).toBe("unknown (registry unreachable)");
  });

  it("gives up on a registry request that stalls", async () => {
    const fetcher = vi.fn(
      (_url: string, init?: RequestInit) =>
        new Promise<Response>((_, reject) =>
          init?.signal?.addEventListener("abort", () =>
            reject(init.signal?.reason),
          ),
        ),
    );
    const licenses = await lookupLicenses(
      ["slow@1.0.0"],
      fetcher as unknown as typeof fetch,
      20,
    );
    expect(licenses.get("slow@1.0.0")).toBe("unknown (registry unreachable)");
  });

  it("stops after the lookup cap", async () => {
    const fetcher = vi.fn(() => respond({ license: "MIT" }));
    const packages = Array.from({ length: 250 }, (_, i) => `p${i}@1.0.0`);
    const licenses = await lookupLicenses(
      packages,
      fetcher as unknown as typeof fetch,
    );
    expect(licenses.size).toBe(200);
  });
});
