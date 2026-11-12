import { describe, expect, it } from "vitest";
import {
  bunfigWritesExact,
  findUnpinned,
  type Manifest,
} from "./check-dependency-pins";

const manifest = (path: string, pkg: Manifest["pkg"]): Manifest => ({
  path,
  pkg,
});

const specs = (manifests: Manifest[]) =>
  findUnpinned(manifests).map((v) => `${v.section}.${v.name}`);

describe("findUnpinned", () => {
  it("accepts exact versions, prereleases and exact aliases", () => {
    const root = manifest("package.json", {
      name: "root",
      dependencies: { next: "16.2.6", left: "1.0.0-beta.2" },
      devDependencies: { typescript7: "npm:typescript@7.0.2" },
      optionalDependencies: { "@img/sharp-linux-x64": "0.35.5" },
      overrides: { react: "19.2.6" },
    });
    expect(findUnpinned([root])).toEqual([]);
  });

  it.each([
    "^1.2.3",
    "~1.2.3",
    "*",
    "latest",
    ">=1.2.3",
    "1.x",
    "1.2",
    "",
  ])("rejects the range %j", (spec) => {
    const root = manifest("package.json", { dependencies: { left: spec } });
    expect(specs([root])).toEqual(["dependencies.left"]);
  });

  it("rejects an alias to a range", () => {
    const root = manifest("package.json", {
      devDependencies: { ts: "npm:typescript@^7.0.0" },
    });
    expect(specs([root])).toEqual(["devDependencies.ts"]);
  });

  it("checks every section, including overrides", () => {
    const root = manifest("package.json", {
      dependencies: { a: "^1.0.0" },
      devDependencies: { b: "^1.0.0" },
      optionalDependencies: { c: "^1.0.0" },
      overrides: { d: "^1.0.0" },
    });
    expect(specs([root])).toEqual([
      "dependencies.a",
      "devDependencies.b",
      "optionalDependencies.c",
      "overrides.d",
    ]);
  });

  it("leaves peerDependencies as ranges", () => {
    const lib = manifest("packages/lib/package.json", {
      peerDependencies: { react: "^19.0.0" },
    });
    expect(findUnpinned([lib])).toEqual([]);
  });

  it("requires workspace:* for a workspace package, from any manifest", () => {
    const core = manifest("packages/core/package.json", {
      name: "@pensar/core",
    });
    const app = manifest("console/package.json", {
      name: "console",
      dependencies: { "@pensar/core": "workspace:*" },
    });
    expect(findUnpinned([core, app])).toEqual([]);

    for (const spec of ["*", "1.0.0", "workspace:^"]) {
      const loose = manifest("console/package.json", {
        dependencies: { "@pensar/core": spec },
      });
      const [violation] = findUnpinned([core, loose]);
      expect(violation).toMatchObject({
        name: "@pensar/core",
        spec,
        fix: "use `workspace:*`",
      });
    }
  });

  it("rejects workspace:* for a package that is not in the workspace", () => {
    const root = manifest("package.json", {
      dependencies: { lodash: "workspace:*" },
    });
    expect(specs([root])).toEqual(["dependencies.lodash"]);
  });

  it("rejects a nested override it cannot verify", () => {
    const root = manifest("package.json", {
      overrides: { parent: { child: "1.0.0" } },
    });
    expect(specs([root])).toEqual(["overrides.parent"]);
  });

  it("reports the manifest and a fix for each finding", () => {
    const app = manifest("console/package.json", {
      dependencies: { left: "^1.0.0" },
    });
    expect(findUnpinned([app])).toEqual([
      {
        path: "console/package.json",
        section: "dependencies",
        name: "left",
        spec: "^1.0.0",
        fix: "use the exact version from bun.lock",
      },
    ]);
  });

  it("fails loudly on a section that is not an object", () => {
    const root = manifest("package.json", { dependencies: "nope" });
    expect(() => findUnpinned([root])).toThrow(/not an object/);
  });
});

describe("bunfigWritesExact", () => {
  it("finds exact = true under [install]", () => {
    expect(bunfigWritesExact("[install]\nexact = true\n")).toBe(true);
    expect(
      bunfigWritesExact(
        "[install]\n# pin\nminimumReleaseAge = 1\nexact=true # yes\n",
      ),
    ).toBe(true);
  });

  it("rejects a missing, false, commented or misplaced setting", () => {
    expect(bunfigWritesExact("[install]\nminimumReleaseAge = 1\n")).toBe(false);
    expect(bunfigWritesExact("[install]\nexact = false\n")).toBe(false);
    expect(bunfigWritesExact("[install]\n# exact = true\n")).toBe(false);
    expect(bunfigWritesExact("[test]\nexact = true\n")).toBe(false);
  });
});
