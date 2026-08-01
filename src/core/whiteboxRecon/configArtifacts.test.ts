import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { extractConfigArtifacts } from "./configArtifacts";
import { inventoryRepository } from "./inventory";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

describe("configuration artifact extraction", () => {
  it("extracts literal identities deterministically and strips URL credentials", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "apex-whitebox-config-"));
    temporaryDirectories.push(root);
    await writeFile(
      path.join(root, "production.json"),
      [
        "{",
        '  "database": {',
        '    "host": "primary.abc.us-east-1.rds.amazonaws.com",',
        '    "port": 5432',
        "  },",
        '  "PUBLIC_URL": "https://api.example.test/v1",',
        '  "REDIS_URL": "redis://:super-secret@cache.example.test:6379/0"',
        "}",
      ].join("\n"),
    );
    const result = await extractConfigArtifacts(
      await inventoryRepository(root),
      [
        {
          id: "application-test",
          name: "test",
          source_roots: ["."],
          languages: [],
          frameworks: [],
          domains: [],
        },
      ],
    );

    expect(result.handled_files).toEqual(["production.json"]);
    expect(result.unresolved).toEqual([]);
    expect(result.resources).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "database",
          provider: "AWS RDS",
          identifier: "primary.abc.us-east-1.rds.amazonaws.com:5432",
          source_line: 3,
        }),
        expect.objectContaining({
          type: "cache",
          provider: "Redis",
          identifier: "redis://cache.example.test:6379/0",
          source_line: 7,
        }),
      ]),
    );
    expect(JSON.stringify(result)).not.toContain("super-secret");
    expect(result.surfaces).toContainEqual(
      expect.objectContaining({
        type: "network",
        path_or_name: "https://api.example.test/v1",
        source_line: 6,
      }),
    );
    expect(
      result.surfaces.some(
        (surface) =>
          surface.path_or_name.includes("rds.amazonaws.com") ||
          surface.path_or_name === "port:5432",
      ),
    ).toBe(false);
    expect(result.domains).toContainEqual(
      expect.objectContaining({ domain: "api.example.test", source_line: 6 }),
    );
  });

  it("uses planner ownership rules for shared configuration roots", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "apex-whitebox-config-"));
    temporaryDirectories.push(root);
    await writeFile(
      path.join(root, "shared.json"),
      '{\n  "PUBLIC_URL": "https://shared.example.test"\n}\n',
    );
    const result = await extractConfigArtifacts(
      await inventoryRepository(root),
      [
        application("application-api", "."),
        application("application-worker", "apps/worker"),
      ],
      [
        {
          path_prefix: "shared.json",
          application_id: "application-worker",
          reason: "Shared public configuration belongs to the worker",
        },
      ],
    );

    expect(result.unresolved).toEqual([]);
    expect(result.surfaces).toContainEqual(
      expect.objectContaining({ application_id: "application-worker" }),
    );
  });
});

function application(id: string, root: string) {
  return {
    id,
    name: id,
    source_roots: [root],
    languages: [],
    frameworks: [],
    domains: [],
  };
}
