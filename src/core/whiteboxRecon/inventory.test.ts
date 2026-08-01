import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createEvidenceBundles } from "./bundles";
import { extractFormalArtifactSurfaces } from "./formalArtifacts";
import { inventoryRepository } from "./inventory";
import { scanRepositoryForCandidates } from "./selectors";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

describe("whitebox recon inventory and selectors", () => {
  it("accounts for first-party files and records excluded dependency directories", async () => {
    const root = await createRepository();
    await mkdir(path.join(root, "src"), { recursive: true });
    await mkdir(path.join(root, "node_modules", "dependency"), {
      recursive: true,
    });
    await writeFile(path.join(root, "package.json"), '{"name":"api"}\n');
    await writeFile(path.join(root, "src", "server.ts"), "serve();\n");
    await writeFile(
      path.join(root, "node_modules", "dependency", "index.js"),
      "thirdParty();\n",
    );
    await writeFile(path.join(root, "package-lock.json"), "{}\n");

    const inventory = await inventoryRepository(root);

    expect(inventory.files.map((file) => file.path)).toEqual([
      "package-lock.json",
      "package.json",
      "src/server.ts",
    ]);
    expect(
      inventory.files.find((file) => file.path === "package-lock.json")
        ?.relevance,
    ).toBe("excluded");
    expect(inventory.excluded_directories).toContainEqual({
      path: "node_modules",
      reason: "third-party-dependencies",
    });
  });

  it("scans every analyzable file and assigns every candidate to one stable bundle", async () => {
    const root = await createRepository();
    await mkdir(path.join(root, "src"), { recursive: true });
    await writeFile(
      path.join(root, "package.json"),
      '{"name":"api","scripts":{"start":"node src/server.js"},"dependencies":{"express":"latest"}}\n',
    );
    await writeFile(
      path.join(root, "src", "routes.ts"),
      'router.get("/users/:id", handler);\n',
    );
    await writeFile(path.join(root, "src", "math.ts"), "export const n = 1;\n");
    const inventory = await inventoryRepository(root);

    const first = await scanRepositoryForCandidates(inventory);
    const second = await scanRepositoryForCandidates(inventory);
    const bundles = createEvidenceBundles(first.candidates, [], inventory, {
      maxCandidates: 1,
    });
    const assigned = bundles.flatMap((bundle) =>
      bundle.candidates.map((candidate) => candidate.id),
    );

    expect(first.files).toHaveLength(3);
    expect(
      first.files.find((file) => file.path === "src/math.ts")?.status,
    ).toBe("no-signal");
    expect(first.candidates).toEqual(second.candidates);
    expect(assigned.sort()).toEqual(
      first.candidates.map((candidate) => candidate.id).sort(),
    );
    expect(new Set(assigned).size).toBe(assigned.length);
  });

  it("keeps dependency-connected router evidence in the same bundle", async () => {
    const root = await createRepository();
    await mkdir(path.join(root, "src"), { recursive: true });
    await writeFile(
      path.join(root, "src", "server.ts"),
      [
        'import usersRouter from "./users";',
        'app.use("/v1", usersRouter);',
      ].join("\n"),
    );
    await writeFile(
      path.join(root, "src", "users.ts"),
      'router.get("/users/:id", handler);\n',
    );
    await writeFile(
      path.join(root, "src", "unrelated.ts"),
      'router.get("/health", handler);\n',
    );
    const inventory = await inventoryRepository(root);
    const ledger = await scanRepositoryForCandidates(inventory);
    const bundles = createEvidenceBundles(
      ledger.candidates,
      [
        {
          id: "application-test",
          name: "test",
          source_roots: ["."],
          languages: ["TypeScript"],
          frameworks: ["Express"],
          domains: [],
        },
      ],
      inventory,
      { maxCandidates: 2 },
    );
    const serverCandidate = ledger.candidates.find(
      (candidate) => candidate.path === "src/server.ts",
    );
    const serverBundle = bundles.find((bundle) =>
      bundle.candidates.some((candidate) => candidate.path === "src/server.ts"),
    );

    expect(serverCandidate?.dependency_context).toContainEqual(
      expect.objectContaining({ resolved_path: "src/users.ts" }),
    );
    expect(serverBundle?.candidates.map((candidate) => candidate.path)).toEqual(
      expect.arrayContaining(["src/server.ts", "src/users.ts"]),
    );
  });

  it("lets a bounded literal selector find a custom registration wrapper", async () => {
    const root = await createRepository();
    await writeFile(
      path.join(root, "custom.ts"),
      'publishExternalOperation("SYNC_USERS", handler);\n',
    );
    const inventory = await inventoryRepository(root);
    const ledger = await scanRepositoryForCandidates(inventory, [
      {
        id: "custom-operation",
        category: "http",
        description: "Custom external operation wrapper",
        literals: ["publishExternalOperation("],
        match: "any",
        case_sensitive: true,
        extensions: [".ts"],
        path_contains: [],
      },
    ]);

    expect(ledger.candidates).toEqual([
      expect.objectContaining({
        path: "custom.ts",
        categories: ["http"],
      }),
    ]);
  });

  it("redacts connection credentials from persisted candidate evidence", async () => {
    const root = await createRepository();
    await writeFile(
      path.join(root, ".env"),
      'DATABASE_URL="postgres://alice:hunter2@db.example.test/main"\n',
    );
    const ledger = await scanRepositoryForCandidates(
      await inventoryRepository(root),
    );
    const evidence = ledger.candidates[0]?.snippet ?? "";

    expect(evidence).not.toContain("alice");
    expect(evidence).not.toContain("hunter2");
    expect(evidence).toContain("[REDACTED]");
  });

  it("classifies CI definitions as build files and tests before infrastructure", async () => {
    const root = await createRepository();
    await mkdir(path.join(root, ".buildkite"), { recursive: true });
    await mkdir(path.join(root, "src", "pulumi"), { recursive: true });
    await writeFile(
      path.join(root, ".buildkite", "pipeline.yml"),
      "steps: []\n",
    );
    await writeFile(
      path.join(root, "src", "pulumi", "network.test.ts"),
      "export const endpoint = 'test';\n",
    );
    const inventory = await inventoryRepository(root);

    expect(
      inventory.files.find((file) => file.path === ".buildkite/pipeline.yml")
        ?.kind,
    ).toBe("build");
    expect(
      inventory.files.find((file) => file.path === "src/pulumi/network.test.ts")
        ?.kind,
    ).toBe("test");
  });

  it("extracts OpenAPI operations, GraphQL fields, and gRPC methods without model candidates", async () => {
    const root = await createRepository();
    await writeFile(
      path.join(root, "openapi.yaml"),
      "openapi: 3.0.0\nservers:\n  - url: https://api.example.test/v1\npaths:\n  /users/{id}:\n    get:\n      responses: {}\n",
    );
    await writeFile(
      path.join(root, "schema.graphql"),
      "type Query {\n  user(id: ID!): User\n  organizations: [Organization!]!\n}\n",
    );
    await writeFile(
      path.join(root, "users.proto"),
      "service UserService {\n  rpc GetUser (GetUserRequest) returns (User);\n}\n",
    );
    const inventory = await inventoryRepository(root);
    const result = await extractFormalArtifactSurfaces(inventory, [
      {
        id: "application-test",
        name: "test",
        source_roots: ["."],
        languages: [],
        frameworks: [],
        domains: [],
      },
    ]);

    expect(result.unresolved).toEqual([]);
    expect(result.surfaces).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "http",
          method: "GET",
          path_or_name: "/v1/users/{id}",
          source_file: "openapi.yaml",
          source_line: 6,
        }),
        expect.objectContaining({
          type: "graphql",
          method: "QUERY",
          path_or_name: "Query.user",
          source_file: "schema.graphql",
          source_line: 2,
        }),
        expect.objectContaining({
          type: "graphql",
          path_or_name: "Query.organizations",
          source_file: "schema.graphql",
          source_line: 3,
        }),
        expect.objectContaining({
          type: "grpc",
          method: "RPC",
          path_or_name: "UserService.GetUser",
          source_file: "users.proto",
          source_line: 2,
        }),
      ]),
    );
  });
});

async function createRepository(): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), "apex-whitebox-inventory-"));
  temporaryDirectories.push(root);
  return root;
}
