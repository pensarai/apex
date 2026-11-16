import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { list } from "./index";

let home: string;
let root: string;

beforeEach(async () => {
  home = await mkdtemp(join(os.tmpdir(), "session-list-"));
  root = join(home, ".pensar", "sessions");
  vi.spyOn(os, "homedir").mockReturnValue(home);
  vi.stubEnv("PENSAR_DATA_DIR", join(home, ".pensar"));
});

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  await rm(home, { recursive: true, force: true });
});

function metadata(id: string) {
  const rootPath = join(root, id);
  return {
    id,
    name: id,
    version: "1.0.0",
    targets: ["https://example.test"],
    time: { created: 100, updated: 200 },
    rootPath,
    logsPath: join(rootPath, "logs"),
    findingsPath: join(rootPath, "findings"),
    scratchpadPath: join(rootPath, "scratchpad"),
    pocsPath: join(rootPath, "pocs"),
  };
}

async function persist(id: string, value: unknown) {
  await mkdir(join(root, id), { recursive: true });
  await writeFile(join(root, id, "session.json"), JSON.stringify(value));
}

async function listed() {
  const entries = [];
  for await (const entry of list()) entries.push(entry);
  return entries;
}

describe("local session listing", () => {
  it("skips Console cache stubs and malformed records without changing files", async () => {
    const before = metadata("ses_a");
    const after = metadata("ses_z");
    const stub = {
      id: "ses_stub",
      agentType: "pentest",
      parentSessionId: null,
      status: "completed",
      metadata: null,
    };
    await persist(before.id, before);
    await persist(stub.id, stub);
    await persist("ses_partial", {
      ...metadata("ses_partial"),
      time: { created: 100 },
    });
    await persist("ses_targets", { ...metadata("ses_targets"), targets: null });
    await persist("ses_null", null);
    await persist("ses_corrupt", {});
    await writeFile(join(root, "ses_corrupt", "session.json"), "{");
    await persist(after.id, after);

    expect((await listed()).map((entry) => entry.id).sort()).toEqual([
      before.id,
      after.id,
    ]);
    expect(
      JSON.parse(await readFile(join(root, stub.id, "session.json"), "utf8")),
    ).toEqual(stub);
  });

  it("retains sessions with older configs and additional persisted fields", async () => {
    const legacy = {
      ...metadata("ses_legacy"),
      config: { connectedRepositories: [{ name: "old-repository" }] },
      tokensIn: 123,
    };
    await persist(legacy.id, legacy);
    expect(await listed()).toEqual([legacy]);
  });
});
