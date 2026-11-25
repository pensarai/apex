import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  type Coverage,
  compareScans,
  findingsFromScan,
  GATED_LOCKFILES,
  ignoredPackagesFrom,
  invalidExceptions,
  lockedPackages,
  lookupLicenses,
  type OsvScan,
  packageVersions,
  parseJsonWithTrailingCommas,
  parseOsvConfig,
  renderSummary,
  scanAndCompare,
  severityOf,
  splitBySource,
  unreadPackages,
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
      [{ path: "bun.lock", base: "/base/bun.lock", head: "/head/bun.lock" }],
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
    const [{ result }] = scanAndCompare(
      [{ path: "bun.lock", base: "/base/bun.lock", head: "/head/bun.lock" }],
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
    const [{ result }] = scanAndCompare(
      [{ path: "bun.lock", base: "/base/bun.lock", head: "/head/bun.lock" }],
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

  it("scans every gated lockfile in the same run and gates each against its own base", () => {
    const calls: ScanCall[] = [];
    const lock = "scripts/offsec-sandbox/package-lock.json";
    const results = scanAndCompare(
      [
        { path: "bun.lock", base: "/base/bun.lock", head: "/head/bun.lock" },
        { path: lock, base: "/base/package-lock.json", head: `/head/${lock}` },
      ],
      "osv-scanner.toml",
      fakeScanner(calls, {
        "/base/bun.lock": [qs("2.0.0")],
        "/head/bun.lock": [qs("2.0.0")],
        "/base/package-lock.json": [pkg("left-pad", "1.0.0")],
        [`/head/${lock}`]: [pkg("left-pad", "1.0.0"), qs("2.0.0")],
      }),
    );
    expect(calls).toHaveLength(1);
    expect(calls[0]?.lockfiles).toEqual([
      "/base/bun.lock",
      "/head/bun.lock",
      "/base/package-lock.json",
      `/head/${lock}`,
    ]);
    // qs@2.0.0 is already in bun.lock, but new to the npm lockfile.
    expect(
      results.map((r) => [r.path, r.result.blocking.map((f) => f.pkg)]),
    ).toEqual([
      ["bun.lock", []],
      [lock, ["qs"]],
    ]);
  });

  it("treats every advisory in a lockfile the PR adds as introduced", () => {
    const calls: ScanCall[] = [];
    const [{ result }] = scanAndCompare(
      [{ path: "new/package-lock.json", head: "/head/package-lock.json" }],
      "osv-scanner.toml",
      fakeScanner(calls, { "/head/package-lock.json": [qs("2.0.0")] }),
    );
    expect(calls[0]?.lockfiles).toEqual(["/head/package-lock.json"]);
    expect(result.blocking.map((f) => `${f.pkg}@${f.version}`)).toEqual([
      "qs@2.0.0",
    ]);
  });

  it("passes on the packages the run's exceptions left out", () => {
    const ignoredPackages = new Set(["js-yaml@4.3.2"]);
    const [scanned] = scanAndCompare(
      [{ path: "bun.lock", head: "/head/bun.lock" }],
      "osv-scanner.toml",
      (paths: string[]): OsvScan => ({
        results: paths.map((path) => ({
          source: { path },
          packages: [qs("2.0.0")],
        })),
        ignoredPackages,
      }),
    );
    expect(scanned?.ignored).toBe(ignoredPackages);
  });

  it("fails when the scan fails", () => {
    expect(() =>
      scanAndCompare(
        [{ path: "bun.lock", base: "/base/bun.lock", head: "/head/bun.lock" }],
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
  const read = (total: number, extra: Partial<Coverage> = {}): Coverage => ({
    total,
    other: 0,
    missing: [],
    hidden: [],
    ...extra,
  });
  const fullyRead = { head: read(0), base: read(0) };

  it("names blocking findings, counts existing ones and lists added licenses", () => {
    const base = scanOf(
      pkg("old", "1.0.0", [{ id: "GHSA-old", score: "9.1" }]),
    );
    const head = scanOf(
      pkg("old", "1.0.0", [{ id: "GHSA-old", score: "9.1" }]),
      pkg("new", "1.0.0", [{ id: "GHSA-new", score: "7.2" }]),
    );
    const summary = renderSummary(
      [
        {
          path: "bun.lock",
          result: compareScans(base, head),
          coverage: { head: read(2), base: read(1) },
        },
      ],
      new Map([["new@1.0.0", "MIT"]]),
    );
    expect(summary).toContain(
      "**Blocked:** this PR introduces 1 critical, high or malware advisories in `bun.lock`",
    );
    expect(summary).toContain(
      "| high (7.2) | `new@1.0.0` | GHSA-new | yes | GHSA-new summary |",
    );
    expect(summary).toContain("Not blocking: 1 critical.");
    expect(summary).toContain(
      "osv-scanner read all 2 registry packages locked in `bun.lock`.",
    );
    expect(summary).not.toContain("Not gated");
    expect(summary).toContain("| `new@1.0.0` | MIT |");
  });

  it("says nothing was introduced when the PR is clean", () => {
    const summary = renderSummary(
      [
        {
          path: "bun.lock",
          result: compareScans(scanOf(), scanOf()),
          coverage: fullyRead,
        },
      ],
      new Map(),
    );
    expect(summary).toContain(
      "No critical, high or malware advisories introduced",
    );
  });

  it("reports each gated lockfile under its own heading", () => {
    const clean = compareScans(scanOf(), scanOf());
    const blocked = compareScans(
      scanOf(),
      scanOf(pkg("new", "1.0.0", [{ id: "GHSA-new", score: "9.8" }])),
    );
    const summary = renderSummary(
      [
        { path: "bun.lock", result: clean, coverage: fullyRead },
        {
          path: "scripts/offsec-sandbox/package-lock.json",
          result: blocked,
          coverage: fullyRead,
        },
      ],
      new Map(),
    );
    expect(summary).toContain(
      "No critical, high or malware advisories introduced in `bun.lock`.",
    );
    expect(summary).toContain(
      "**Blocked:** this PR introduces 1 critical, high or malware advisories in `scripts/offsec-sandbox/package-lock.json`",
    );
  });

  it("blocks on unread head packages and warns on unread base packages", () => {
    const missing = Array.from(
      { length: 22 },
      (_, i) => `p${String(i).padStart(2, "0")}@1.0.0`,
    );
    const summary = renderSummary(
      [
        {
          path: "bun.lock",
          result: compareScans(scanOf(), scanOf()),
          coverage: {
            head: read(40, { missing, other: 3 }),
            base: read(40, { missing: ["old@1.0.0"] }),
          },
        },
      ],
      new Map(),
    );
    expect(summary).toContain(
      "**Blocked:** osv-scanner did not read 22 of the 40 registry packages locked in `bun.lock`",
    );
    expect(summary).toContain("`p19@1.0.0`, and 2 more.");
    expect(summary).not.toContain("p20@1.0.0");
    expect(summary).toContain(
      "3 workspace, link, file or Git entries are not counted.",
    );
    expect(summary).toContain(
      "**Warning:** osv-scanner did not read 1 of the 40 registry packages in the merge base's `bun.lock`: `old@1.0.0`.",
    );
  });

  it("notes packages hidden by an override and a lockfile new in the PR", () => {
    const summary = renderSummary(
      [
        {
          path: "new/bun.lock",
          result: compareScans(scanOf(), scanOf()),
          coverage: {
            head: read(5, { hidden: ["js-yaml@4.3.2"] }),
            base: null,
          },
        },
      ],
      new Map(),
    );
    expect(summary).toContain(
      "osv-scanner read all 5 registry packages locked in `new/bun.lock`, apart from 1 that `[[PackageOverrides]]` entries hide with `ignore = true`.",
    );
    expect(summary).toContain(
      "`new/bun.lock` is new in this PR, so every advisory in it counts as introduced.",
    );
  });
});

describe("GATED_LOCKFILES", () => {
  it("gates bun.lock and the sandbox image lockfile, and each exists", () => {
    expect(GATED_LOCKFILES).toEqual([
      "bun.lock",
      "scripts/offsec-sandbox/package-lock.json",
    ]);
    for (const path of GATED_LOCKFILES)
      expect(existsSync(join(import.meta.dirname, "..", path))).toBe(true);
  });

  it("reads every entry of the sandbox image lockfile as a registry package", () => {
    const path = "scripts/offsec-sandbox/package-lock.json";
    const locked = lockedPackages(
      path,
      readFileSync(join(import.meta.dirname, "..", path), "utf8"),
    );
    expect(locked.registry.size).toBeGreaterThan(0);
    const manifest = JSON.parse(
      readFileSync(
        join(import.meta.dirname, "offsec-sandbox", "package.json"),
        "utf8",
      ),
    ) as { dependencies: Record<string, string> };
    for (const [name, version] of Object.entries(manifest.dependencies))
      expect(locked.registry).toContain(`${name}@${version}`);
    expect(locked.other).toBe(0);
  });
});

describe("parseJsonWithTrailingCommas", () => {
  it("drops trailing commas before a closing bracket, at any depth and across lines", () => {
    expect(
      parseJsonWithTrailingCommas('{ "a": [1, 2,], "b": { "c": "d", },\n}'),
    ).toEqual({ a: [1, 2], b: { c: "d" } });
  });

  it("keeps commas, brackets and escaped quotes inside strings", () => {
    expect(
      parseJsonWithTrailingCommas('{ "a": ",}", "b": "x\\",]", }'),
    ).toEqual({ a: ",}", b: 'x",]' });
  });

  it("fails on JSON it cannot read", () => {
    expect(() => parseJsonWithTrailingCommas('{ "a": ')).toThrow(SyntaxError);
  });
});

// A bun.lock as bun writes it: trailing commas, workspaces, nested copies.
const BUN_LOCK = `{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "root", "dependencies": { "left-pad": "1.3.0", }, },
  },
  "packages": {
    "left-pad": ["left-pad@1.3.0", "", {}, "sha512-a"],
    "@scope/pkg": ["@scope/pkg@2.0.0-beta.1", "", {}, "sha512-b"],
    "foo/left-pad": ["left-pad@1.3.0", "", {}, "sha512-a"],
    "bar/left-pad": ["left-pad@1.2.0", "", {}, "sha512-c"],
    "string-width-cjs": ["string-width@4.2.3", "", {}, "sha512-d"],
    "showcase": ["showcase@workspace:showcase"],
    "linked": ["linked@link:../linked", {}],
    "local": ["local@file:../local", {}],
    "rooted": ["rooted@root:", {}],
    "gitdep": ["gitdep@git+https://github.com/a/gitdep.git#0123456", {}, "0123456"],
    "ghdep": ["ghdep@github:a/ghdep#0123456", {}, "a-ghdep-0123456"],
    "tardep": ["tardep@https://example.com/tardep-1.0.0.tgz", {}],
    "localtar": ["localtar@./vendor/localtar-1.0.0.tgz", {}],
    "uptar": ["uptar@../vendor/uptar-1.0.0.tgz", {}],
    "abstar": ["abstar@/opt/vendor/abstar-1.0.0.tgz", {}],
  },
}
`;

const PACKAGE_LOCK = JSON.stringify({
  name: "root",
  lockfileVersion: 3,
  packages: {
    "": { name: "root", workspaces: ["packages/a"] },
    "packages/a": { name: "a", version: "0.1.0" },
    "node_modules/a": { resolved: "packages/a", link: true },
    "node_modules/minimist": {
      version: "1.2.5",
      resolved: "https://registry.npmjs.org/minimist/-/minimist-1.2.5.tgz",
    },
    "node_modules/foo/node_modules/minimist": { version: "1.2.5" },
    "node_modules/foo": { version: "2.0.0", dev: true },
    "node_modules/my-alias": { name: "lodash", version: "4.17.20" },
    "node_modules/@scope/x": { version: "1.0.0" },
    "node_modules/gitdep": {
      version: "1.0.0",
      resolved: "git+ssh://git@github.com/a/gitdep.git#0123456",
    },
    "node_modules/tardep": {
      version: "1.0.0",
      resolved: "https://example.com/tardep-1.0.0.tgz",
    },
  },
});

describe("lockedPackages", () => {
  it("reads the distinct registry packages of a bun.lock, aliases under their real name", () => {
    const locked = lockedPackages("bun.lock", BUN_LOCK);
    expect([...locked.registry].sort()).toEqual([
      "@scope/pkg@2.0.0-beta.1",
      "left-pad@1.2.0",
      "left-pad@1.3.0",
      "string-width@4.2.3",
    ]);
    // Workspace, link, file, root, Git, GitHub, tarball URL and local tarball entries.
    expect(locked.other).toBe(10);
  });

  it("reads the distinct registry packages of a package-lock.json", () => {
    const locked = lockedPackages("x/package-lock.json", PACKAGE_LOCK);
    expect([...locked.registry].sort()).toEqual([
      "@scope/x@1.0.0",
      "foo@2.0.0",
      "lodash@4.17.20",
      "minimist@1.2.5",
      "tardep@1.0.0",
    ]);
    // The workspace target, its link and the Git dependency.
    expect(locked.other).toBe(3);
  });

  it("fails on a bun.lock entry it cannot read, such as one with an empty version", () => {
    const lock = (entry: string) => `{ "packages": { "foo": ${entry}, }, }`;
    expect(() =>
      lockedPackages("bun.lock", lock('["foo@", "", {}, "sha512-a"]')),
    ).toThrow('cannot read the version of "foo" (foo@)');
    expect(() => lockedPackages("bun.lock", lock('["foo"]'))).toThrow(
      'cannot read the package entry "foo"',
    );
    expect(() => lockedPackages("bun.lock", lock('"foo@1.0.0"'))).toThrow(
      'cannot read the package entry "foo"',
    );
    expect(() => lockedPackages("bun.lock", lock("[]"))).toThrow(
      'cannot read the package entry "foo"',
    );
    expect(() => lockedPackages("bun.lock", lock('["foo@latest"]'))).toThrow(
      "cannot read the version",
    );
  });

  it("fails on a package-lock.json entry without a version it can read", () => {
    const lock = (entry: object) =>
      JSON.stringify({ packages: { "": {}, "node_modules/foo": entry } });
    expect(() => lockedPackages("package-lock.json", lock({}))).toThrow(
      'cannot read the version of "node_modules/foo"',
    );
    expect(() =>
      lockedPackages("package-lock.json", lock({ version: "" })),
    ).toThrow("cannot read the version");
  });

  it("fails on a lockfile with no packages map, or one it does not read", () => {
    expect(() =>
      lockedPackages("bun.lock", '{ "lockfileVersion": 1, }'),
    ).toThrow("no packages map");
    expect(() =>
      lockedPackages(
        "package-lock.json",
        JSON.stringify({ lockfileVersion: 1, dependencies: {} }),
      ),
    ).toThrow("no packages map");
    expect(() => lockedPackages("yarn.lock", "")).toThrow(
      "reads bun.lock and package-lock.json only",
    );
    expect(() => lockedPackages("bun.lock", '{ "packages": ')).toThrow(
      SyntaxError,
    );
  });
});

describe("unreadPackages", () => {
  const locked = {
    registry: new Set(["left-pad@1.3.0", "js-yaml@4.3.2", "@scope/pkg@2.0.0"]),
    other: 2,
  };

  it("passes when osv-scanner read every registry package", () => {
    const scan = scanOf(
      pkg("left-pad", "1.3.0"),
      pkg("js-yaml", "4.3.2"),
      pkg("@scope/pkg", "2.0.0"),
      pkg("ws", "workspace:ws"),
    );
    expect(unreadPackages(locked, scan, new Set())).toEqual({
      total: 3,
      other: 2,
      missing: [],
      hidden: [],
    });
  });

  it("names each registry package the scan is missing", () => {
    expect(
      unreadPackages(locked, scanOf(pkg("left-pad", "1.3.0")), new Set())
        .missing,
    ).toEqual(["@scope/pkg@2.0.0", "js-yaml@4.3.2"]);
  });

  it("counts a package osv-scanner read with an empty version as unread", () => {
    // osv-scanner 2.7.1 reads a malformed bun.lock entry such as ["js-yaml@"] as js-yaml with no version.
    const scan = scanOf(
      pkg("left-pad", "1.3.0"),
      pkg("js-yaml", ""),
      pkg("@scope/pkg", "2.0.0"),
    );
    expect(unreadPackages(locked, scan, new Set()).missing).toEqual([
      "js-yaml@4.3.2",
    ]);
  });

  it("excepts a package osv-scanner says an override left out, and only that version", () => {
    const scan = scanOf(pkg("left-pad", "1.3.0"), pkg("@scope/pkg", "2.0.0"));
    expect(unreadPackages(locked, scan, new Set(["js-yaml@4.3.2"]))).toEqual({
      total: 3,
      other: 2,
      missing: [],
      hidden: ["js-yaml@4.3.2"],
    });
    expect(
      unreadPackages(locked, scan, new Set(["js-yaml@4.0.0"])).missing,
    ).toEqual(["js-yaml@4.3.2"]);
  });

  it("matches the names and versions osv-scanner 2.7.1 reports for each kind of bun.lock entry", () => {
    const scan = scanOf(
      pkg("left-pad", "1.3.0"),
      pkg("left-pad", "1.2.0"),
      pkg("@scope/pkg", "2.0.0-beta.1"),
      pkg("string-width", "4.2.3"),
      pkg("showcase", "workspace:showcase"),
      pkg("https://github.com/a/gitdep", ""),
    );
    expect(
      unreadPackages(lockedPackages("bun.lock", BUN_LOCK), scan, new Set())
        .missing,
    ).toEqual([]);
  });
});

describe("ignoredPackagesFrom", () => {
  it("reads each npm package osv-scanner 2.7.1 logs as filtered out, scoped names included", () => {
    const log = [
      "Scanned /w/bun.lock file and found 479 packages",
      "Package npm/@babel/code-frame/7.29.0 has been filtered out because: generated code only",
      "Package npm/js-yaml/4.3.2 has been filtered out because: a reason: with colons",
      "Package PyPI/requests/2.0.0 has been filtered out because: not npm",
      "Filtered 3 ignored package/s from the scan.",
      "GHSA-1234 and 1 alias have been filtered out because: unrelated advisory",
    ].join("\n");
    expect(ignoredPackagesFrom(log)).toEqual(
      new Set(["@babel/code-frame@7.29.0", "js-yaml@4.3.2"]),
    );
  });

  it("excuses nothing when the log has no such line", () => {
    expect(ignoredPackagesFrom("")).toEqual(new Set());
    expect(ignoredPackagesFrom(undefined)).toEqual(new Set());
    expect(ignoredPackagesFrom("Package js-yaml was skipped")).toEqual(
      new Set(),
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
