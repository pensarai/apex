import { describe, expect, it, vi } from "vitest";
import {
  compareScans,
  findingsFromScan,
  invalidExceptions,
  lookupLicenses,
  type OsvScan,
  packageVersions,
  parseOsvConfig,
  renderSummary,
  scanAndCompare,
  severityOf,
  splitBySource,
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
        package: { name, ecosystem: "npm" },
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

  it("blocks a second affected version added beside one already there", () => {
    const base = scanOf(pkg("qs", "1.0.0", [{ id: "GHSA-qs", score: "7.5" }]));
    const head = scanOf(
      pkg("qs", "1.0.0", [{ id: "GHSA-qs", score: "7.5" }]),
      pkg("qs", "2.0.0", [{ id: "GHSA-qs", score: "7.5" }]),
    );
    const result = compareScans(base, head);
    expect(result.blocking.map((f) => f.version)).toEqual(["2.0.0"]);
    expect(result.existing.map((f) => f.version)).toEqual(["1.0.0"]);
  });

  it("lets an affected version replace one the PR removed", () => {
    const base = scanOf(
      pkg("qs", "1.0.0", [{ id: "GHSA-qs", score: "7.5" }]),
      pkg("qs", "2.0.0", [{ id: "GHSA-qs", score: "7.5" }]),
    );
    const head = scanOf(
      pkg("qs", "2.0.0", [{ id: "GHSA-qs", score: "7.5" }]),
      pkg("qs", "3.0.0", [{ id: "GHSA-qs", score: "7.5" }]),
    );
    expect(compareScans(base, head).blocking).toEqual([]);
  });

  it("reads the fix from the reported package only", () => {
    const a = pkg("a", "1.0.0", [
      { id: "GHSA-multi", score: "8", fixed: false },
    ]);
    a.vulnerabilities[0]?.affected.push({
      package: { name: "other", ecosystem: "npm" },
      ranges: [{ events: [{ introduced: "0" }, { fixed: "2.0.0" }] }],
    });
    expect(findingsFromScan(scanOf(a))[0]?.fixAvailable).toBe(false);
  });

  it("finds a fix listed on any record in the advisory group", () => {
    const a = pkg("a", "1.0.0", [
      { id: "CVE-2026-9", score: "8", fixed: false },
    ]);
    a.groups[0]?.ids.push("GHSA-9");
    a.vulnerabilities.push({
      id: "GHSA-9",
      summary: "",
      affected: [
        {
          package: { name: "a", ecosystem: "npm" },
          ranges: [{ events: [{ introduced: "0" }, { fixed: "1.0.1" }] }],
        },
      ],
    });
    expect(findingsFromScan(scanOf(a))[0]?.fixAvailable).toBe(true);
  });

  it("handles a scan with no results", () => {
    expect(compareScans({ results: null }, { results: [] }).introduced).toEqual(
      [],
    );
  });
});

describe("splitBySource", () => {
  const result = (path: string, ...packages: ReturnType<typeof pkg>[]) => ({
    source: { path },
    packages,
  });

  it("splits a combined scan by the path each lockfile was given", () => {
    const [base, head] = splitBySource(
      {
        results: [
          result("/head/bun.lock", pkg("qs", "2.0.0")),
          result("/base/bun.lock", pkg("qs", "1.0.0")),
        ],
      },
      ["/base/bun.lock", "/head/bun.lock"],
    );
    expect([...packageVersions(base)]).toEqual(["qs@1.0.0"]);
    expect([...packageVersions(head)]).toEqual(["qs@2.0.0"]);
  });

  it("matches Windows paths, which osv-scanner reports with forward slashes", () => {
    const [head] = splitBySource(
      { results: [result("C:/src/repo/bun.lock", pkg("qs", "2.0.0"))] },
      ["C:\\src\\repo\\bun.lock"],
    );
    expect([...packageVersions(head)]).toEqual(["qs@2.0.0"]);
  });

  it("fails when a lockfile has no results rather than reading it as clean", () => {
    expect(() =>
      splitBySource(
        { results: [result("/base/bun.lock", pkg("qs", "1.0.0"))] },
        ["/base/bun.lock", "/head/bun.lock"],
      ),
    ).toThrow("no results for /head/bun.lock");
  });

  it("fails on results from a lockfile it did not ask for", () => {
    expect(() =>
      splitBySource({ results: [result("bun.lock", pkg("qs", "1.0.0"))] }, [
        "bun.lock",
        "/elsewhere/bun.lock",
      ]),
    ).toThrow();
    expect(() =>
      splitBySource(
        {
          results: [
            result("/base/bun.lock", pkg("qs", "1.0.0")),
            result("/head/bun.lock", pkg("qs", "1.0.0")),
            result("/other/bun.lock", pkg("qs", "1.0.0")),
          ],
        },
        ["/base/bun.lock", "/head/bun.lock"],
      ),
    ).toThrow("unexpected source: /other/bun.lock");
  });
});

describe("scanAndCompare", () => {
  type ScanCall = { lockfiles: string[]; config?: string; download?: boolean };
  const qs = (version: string) =>
    pkg("qs", version, [{ id: "GHSA-qs", score: "7.5" }]);
  // Stands in for osv-scanner over several lockfiles: the config"s override
  // accepts GHSA-qs on qs@1.0.0 only.
  const fakeScanner =
    (calls: ScanCall[], lockfiles: Record<string, ReturnType<typeof pkg>[]>) =>
    (
      paths: string[],
      config?: string,
      opts: { download?: boolean } = {},
    ): OsvScan => {
      calls.push({ lockfiles: paths, config, ...opts });
      return {
        results: paths.map((path) => ({
          source: { path },
          packages: (lockfiles[path] ?? []).filter(
            (p) =>
              !(
                config &&
                p.package.name === "qs" &&
                p.package.version === "1.0.0"
              ),
          ),
        })),
      };
    };

  it("scans both lockfiles in one run, with the config and one database download", () => {
    const calls: ScanCall[] = [];
    scanAndCompare(
      "/base/bun.lock",
      "/head/bun.lock",
      "osv-scanner.toml",
      fakeScanner(calls, {
        "/base/bun.lock": [qs("1.0.0")],
        "/head/bun.lock": [qs("1.0.0")],
      }),
    );
    expect(calls).toEqual([
      {
        lockfiles: ["/base/bun.lock", "/head/bun.lock"],
        config: "osv-scanner.toml",
        download: true,
      },
    ]);
  });

  it("blocks a new affected version beside one an exception accepts", () => {
    const result = scanAndCompare(
      "/base/bun.lock",
      "/head/bun.lock",
      "osv-scanner.toml",
      fakeScanner([], {
        "/base/bun.lock": [qs("1.0.0")],
        "/head/bun.lock": [qs("1.0.0"), qs("2.0.0")],
      }),
    );
    expect(result.blocking.map((f) => f.version)).toEqual(["2.0.0"]);
  });

  it("blocks an advisory in an ecosystem only the head lockfile uses", () => {
    const requests = pkg("requests", "2.0.0", [
      { id: "GHSA-req", score: "9.1" },
    ]);
    requests.package.ecosystem = "PyPI";
    const result = scanAndCompare(
      "/base/bun.lock",
      "/head/bun.lock",
      "osv-scanner.toml",
      fakeScanner([], {
        "/base/bun.lock": [pkg("left-pad", "1.0.0")],
        "/head/bun.lock": [pkg("left-pad", "1.0.0"), requests],
      }),
    );
    expect(result.blocking.map((f) => `${f.pkg}@${f.version}`)).toEqual([
      "requests@2.0.0",
    ]);
  });

  it("fails when the scan fails", () => {
    expect(() =>
      scanAndCompare(
        "/base/bun.lock",
        "/head/bun.lock",
        "osv-scanner.toml",
        () => {
          throw new Error("osv-scanner failed (exit 127)");
        },
      ),
    ).toThrow("exit 127");
  });
});

describe("parseOsvConfig and invalidExceptions", () => {
  it("rejects a key set twice in one entry, in any case", () => {
    const toml = [
      "[[PackageOverrides]]",
      'name = "qs"',
      "ignore = false",
      "Ignore = true",
      'reason = "dev only"',
    ].join("\n");
    expect(() => parseOsvConfig(toml)).toThrow(
      'osv-scanner.toml line 4: "Ignore" is set twice in one entry',
    );
  });

  it("reads entries, trailing comments, spaced headers and a # inside a string", () => {
    const toml = [
      "# header comment",
      "[[IgnoredVulns]] # temporary",
      'id = "GHSA-1" # trailing comment',
      "ignoreUntil = 2027-01-01",
      'reason = "dev server only, \\"quoted\\" #not-a-comment"',
      "",
      "[[ IgnoredVulns ]]",
      "id = 'GHSA-2'",
    ].join("\n");
    const config = parseOsvConfig(toml);
    expect(config.IgnoredVulns).toEqual([
      {
        id: "GHSA-1",
        ignoreuntil: "2027-01-01",
        reason: 'dev server only, "quoted" #not-a-comment',
      },
      { id: "GHSA-2" },
    ]);
    expect(invalidExceptions(config)).toEqual(["GHSA-2 has no reason"]);
  });

  it("reads a commented-out example as no entries", () => {
    expect(parseOsvConfig('# [[IgnoredVulns]]\n# id = "GHSA-x"\n')).toEqual({
      IgnoredVulns: [],
      PackageOverrides: [],
    });
  });

  it("requires a reason on every package override that hides vulnerabilities", () => {
    const toml = [
      "[[PackageOverrides]]",
      'name = "a"',
      "ignore = true",
      "[[PackageOverrides]]",
      'name = "b"',
      "vulnerability.ignore = true",
      "[[PackageOverrides]]",
      'name = "d"',
      "vulnerability.ignore = true",
      'reason = "vendored and patched"',
      "[[PackageOverrides]]",
      'name = "e"',
      'license.override = ["MIT"]',
      "[[PackageOverrides]]",
      'name = "f"',
      "license.ignore = true",
    ].join("\n");
    expect(invalidExceptions(parseOsvConfig(toml))).toEqual([
      "a ignores vulnerabilities without a reason",
      "b ignores vulnerabilities without a reason",
    ]);
  });

  it("matches table and key names case-insensitively, as osv-scanner does", () => {
    const toml = [
      "[[ignoredvulns]]",
      'ID = "GHSA-1"',
      "[[PACKAGEOVERRIDES]]",
      'Name = "a"',
      "Ignore = true",
      "[[PackageOverrides]]",
      'name = "b"',
      "Vulnerability.IGNORE = true",
      'Reason = "patched in our fork"',
    ].join("\n");
    expect(invalidExceptions(parseOsvConfig(toml))).toEqual([
      "GHSA-1 has no reason",
      "a ignores vulnerabilities without a reason",
    ]);
  });

  it.each([
    ['[[Unknown]]\nid = "x"', /does not check \[\[Unknown\]\]/],
    ["[PackageOverrides.vulnerability]\nignore = true", /cannot check/],
    ['[[IgnoredVulns]]\nreason = """\nwhy\n"""', /multi-line/],
    ["[[IgnoredVulns]]\nid = \n", /cannot read/],
    ['[[IgnoredVulns]]\nid = "unterminated\n', /cannot read the string/],
    [
      '[[PackageOverrides]]\nname = "x"\nvulnerability = { ignore = true }',
      /dotted keys/,
    ],
    [
      '[[PackageOverrides]]\nname = "x"\nvulnerability = { "ignore" = true }',
      /dotted keys/,
    ],
    ['[[IgnoredVulns]]\nid = { value = "GHSA-1" }', /dotted keys/],
    ['[[PackageOverrides]]\n"vulnerability".ignore = true', /cannot read/],
    ['[[PackageOverrides]]\nvulnerability."ignore" = true', /cannot read/],
    ['IgnoredVulns = [{ id = "GHSA-1" }]', /no top-level settings/],
    [
      'PackageOverrides = [{ name = "x", ignore = true }]',
      /no top-level settings/,
    ],
    ['GoVersionOverride = "1.22"', /no top-level settings/],
  ])("fails closed on %j", (toml, error) => {
    expect(() => parseOsvConfig(toml)).toThrow(error);
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
