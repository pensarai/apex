import { mkdirSync, mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Tool } from "ai";
import { describe, expect, it, vi } from "vitest";
import type { SessionInfo } from "../../../session";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import {
  documentBoundary,
  documentComponent,
  documentControl,
  documentFlow,
  readDocumentedTopology,
  retireRecord,
  reviewTopologyRecords,
  updateRecord,
} from "./documentTopology";
import {
  diffTopology,
  loadTopology,
  readRecordFiles,
  resolveTopology,
  seedFromBaseline,
  writeRecord,
  writeRecordFiles,
} from "./topologyRecords";
import type { ToolContext } from "./types";

function makeCtx(id = "ses_base"): ToolContext {
  const root = mkdtempSync(join(tmpdir(), "apex-records-"));
  return {
    subagentSpawner: inProcessSubagentSpawner,
    session: {
      id,
      targets: ["https://app.example"],
      rootPath: root,
    } as unknown as SessionInfo,
    agentCwd: root,
    target: "https://app.example",
  };
}

async function run(t: Tool, input: Record<string, unknown>) {
  return (await t.execute?.(
    { toolCallDescription: "test", ...input },
    { toolCallId: "tc", messages: [] },
  )) as Record<string, unknown>;
}

const evidence = [
  { source: "source", detail: "compose", ref: "docker-compose.yml" },
];
const app = (name: string, extra: Record<string, unknown> = {}) => ({
  name,
  kind: "application",
  boundary: "Private",
  exposure: "public",
  endpoints: ["https://app.example"],
  atStake: "Customer orders.",
  trustAssumptions: [],
  evidence,
  ...extra,
});
const db = {
  name: "Postgres",
  kind: "database",
  boundary: "Private",
  exposure: "private",
  atStake: "All rows.",
  trustAssumptions: ["Callers know the password."],
  evidence,
};

async function baseline(ctx: ToolContext) {
  await run(documentBoundary(ctx), {
    name: "Private",
    kind: "subnet",
    evidence,
  });
  await run(documentComponent(ctx), app("Shop API"));
  await run(documentComponent(ctx), db);
  await run(documentFlow(ctx), {
    from: "Shop API",
    to: "Postgres",
    label: "SQL",
    evidence,
  });
  await run(documentControl(ctx), {
    name: "DB password",
    kind: "secret-management",
    appliesTo: ["Postgres"],
    protects: "Password auth.",
    gaps: "Committed in compose.",
    evidence,
  });
}

/** Start an update session seeded from `base`. */
function update(base: ToolContext): ToolContext {
  const ctx = makeCtx("ses_update");
  seedFromBaseline(ctx.session.rootPath, base.session.rootPath);
  return ctx;
}

describe("record identity", () => {
  it("keeps a record's id when it is documented again under the same name", async () => {
    const ctx = makeCtx();
    await baseline(ctx);
    const before = loadTopology(ctx.session.rootPath).components.find(
      (c) => c.name === "Shop API",
    )?.id;
    await run(documentComponent(ctx), app("Shop API", { tech: "Flask" }));
    const after = loadTopology(ctx.session.rootPath).components.filter(
      (c) => c.name === "Shop API",
    );
    expect(after).toHaveLength(1);
    expect(after[0].id).toBe(before);
    expect(after[0].tech).toBe("Flask");
  });

  it("renames in place: same id, and flows and controls follow the new name", async () => {
    const ctx = makeCtx();
    await baseline(ctx);
    const id = loadTopology(ctx.session.rootPath).components.find(
      (c) => c.name === "Postgres",
    )?.id;
    const result = await run(documentComponent(ctx), {
      ...db,
      name: "Orders DB",
      renameFrom: "Postgres",
    });
    expect(result.success).toBe(true);
    const t = loadTopology(ctx.session.rootPath);
    expect(t.components.map((c) => c.name).sort()).toEqual([
      "Orders DB",
      "Shop API",
    ]);
    expect(t.components.find((c) => c.name === "Orders DB")?.id).toBe(id);
    const diagram = readDocumentedTopology(ctx.session.rootPath);
    expect(diagram.flows).toEqual([
      { from: "Shop API", to: "Orders DB", label: "SQL" },
    ]);
    expect(diagram.controls?.[0]?.appliesTo).toEqual(["Orders DB"]);
    expect(reviewTopologyRecords(ctx).map((i) => i.check)).not.toContain(
      "unconnected",
    );
  });

  it("refuses a rename onto a name another record holds, or from an unknown name", async () => {
    const ctx = makeCtx();
    await baseline(ctx);
    expect(
      await run(documentComponent(ctx), {
        ...db,
        name: "Shop API",
        renameFrom: "Postgres",
      }),
    ).toMatchObject({
      success: false,
      error: "name_taken",
    });
    expect(
      await run(documentComponent(ctx), {
        ...db,
        name: "X",
        renameFrom: "Redis",
      }),
    ).toMatchObject({
      success: false,
      error: "unknown_component",
    });
  });

  it("documenting a flow again with the same endpoints and label updates it rather than adding one", async () => {
    const ctx = makeCtx();
    await baseline(ctx);
    await run(documentFlow(ctx), {
      from: "shop api",
      to: "postgres",
      label: "sql",
      evidence,
    });
    expect(loadTopology(ctx.session.rootPath).flows).toHaveLength(1);
  });

  it("gives records written before ids a stable id from their name, and reuses it", async () => {
    const ctx = makeCtx();
    const dir = join(ctx.session.rootPath, "topology");
    mkdirSync(dir, { recursive: true });
    const legacy = (file: string, record: Record<string, unknown>) =>
      writeFileSync(
        join(dir, file),
        JSON.stringify({ ...record, recordedAt: "2026-01-01T00:00:00.000Z" }),
      );
    legacy("boundary_private_old.json", {
      name: "Private",
      kind: "subnet",
      evidence,
    });
    legacy("component_shop_api_old.json", app("Shop API"));
    legacy("component_postgres_old.json", db);
    legacy("flow_old.json", {
      from: "Shop API",
      to: "Postgres",
      label: "SQL",
      evidence,
    });
    expect(
      loadTopology(ctx.session.rootPath)
        .components.map((c) => c.id)
        .sort(),
    ).toEqual(["component:postgres", "component:shop api"]);
    await run(documentComponent(ctx), app("Shop API", { tech: "Flask" }));
    await run(documentFlow(ctx), {
      from: "Shop API",
      to: "Postgres",
      label: "SQL",
      evidence,
    });
    const t = loadTopology(ctx.session.rootPath);
    expect(t.components.find((c) => c.name === "Shop API")?.id).toBe(
      "component:shop api",
    );
    expect(t.flows).toHaveLength(1);
  });
});

describe("writeRecord", () => {
  it("writes and reads back a record whose key is past the 255-byte name limit", () => {
    const root = mkdtempSync(join(tmpdir(), "apex-records-long-"));
    const title = "attacker replays a signed request ".repeat(10);
    writeRecord(root, "ses_long", "threat", `threat:api|${title}`, {
      id: "thr_long",
      title,
    });
    const stored = readRecordFiles(root);
    expect(stored).toMatchObject([
      { kind: "threat", record: { id: "thr_long" } },
    ]);
    expect(stored.every((s) => Buffer.byteLength(s.file) <= 255)).toBe(true);
  });

  it("keeps two long keys sharing a prefix apart when written in the same millisecond", () => {
    const root = mkdtempSync(join(tmpdir(), "apex-records-long-"));
    const prefix = "attacker replays a signed request ".repeat(10);
    vi.useFakeTimers({ now: new Date("2026-01-01T00:00:00Z") });
    try {
      writeRecord(root, "ses_long", "threat", `threat:api|${prefix}a`, {
        id: "thr_a",
      });
      writeRecord(root, "ses_long", "threat", `threat:api|${prefix}b`, {
        id: "thr_b",
      });
    } finally {
      vi.useRealTimers();
    }
    expect(
      readRecordFiles(root)
        .map((s) => s.record.id)
        .sort(),
    ).toEqual(["thr_a", "thr_b"]);
  });
});

describe("retire_record", () => {
  it("removes a component from the active map and flags what still points at it", async () => {
    const ctx = makeCtx();
    await baseline(ctx);
    const result = await run(retireRecord(ctx), {
      kind: "component",
      name: "Postgres",
      reason: "Removed from docker-compose.yml in abc123.",
      evidence,
    });
    expect(result.success).toBe(true);
    const t = loadTopology(ctx.session.rootPath);
    expect(t.components.map((c) => c.name)).toEqual(["Shop API"]);
    expect(t.retired.map((r) => [r.kind, r.record.name])).toEqual([
      ["component", "Postgres"],
    ]);
    const flagged = reviewTopologyRecords(ctx).filter(
      (i) => i.check === "references-retired",
    );
    expect(flagged.map((i) => i.subject).sort()).toEqual([
      "DB password",
      "Shop API → Postgres (SQL)",
    ]);
  });

  it("retires a flow by its endpoints and label", async () => {
    const ctx = makeCtx();
    await baseline(ctx);
    await run(retireRecord(ctx), {
      kind: "flow",
      from: "Shop API",
      to: "Postgres",
      label: "SQL",
      reason: "Gone.",
      evidence,
    });
    expect(loadTopology(ctx.session.rootPath).flows).toEqual([]);
  });

  it("fails on a record that does not exist", async () => {
    const ctx = makeCtx();
    await baseline(ctx);
    expect(
      await run(retireRecord(ctx), {
        kind: "component",
        name: "Redis",
        reason: "x",
        evidence,
      }),
    ).toMatchObject({
      success: false,
      error: "unknown_component",
    });
  });
});

describe("record files held outside the session", () => {
  it("resolve the same topology in any order as the session's own files", async () => {
    const ctx = makeCtx();
    await baseline(ctx);
    await run(documentComponent(ctx), {
      ...app("Storefront API"),
      renameFrom: "Shop API",
    });
    const files = readRecordFiles(ctx.session.rootPath);
    expect(resolveTopology([...files].reverse())).toEqual(
      loadTopology(ctx.session.rootPath),
    );
  });

  it("write back into a session without overwriting what is there, and refuse unsafe names", async () => {
    const source = makeCtx();
    await baseline(source);
    const files = readRecordFiles(source.session.rootPath);
    const target = makeCtx("ses_recovered");
    expect(writeRecordFiles(target.session.rootPath, files)).toBe(files.length);
    expect(writeRecordFiles(target.session.rootPath, files)).toBe(0);
    expect(loadTopology(target.session.rootPath)).toEqual(
      loadTopology(source.session.rootPath),
    );
    const [first] = files;
    expect(() =>
      writeRecordFiles(target.session.rootPath, [
        { ...first!, file: "../component_x_1.json" },
      ]),
    ).toThrow("unsafe record file name");
  });
});

describe("seedFromBaseline", () => {
  it("copies the baseline's active records with their ids and leaves retired ones behind", async () => {
    const base = makeCtx();
    await baseline(base);
    await run(retireRecord(base), {
      kind: "control",
      name: "DB password",
      reason: "Moved to a secret store.",
      evidence,
    });
    const next = update(base);
    const seeded = loadTopology(next.session.rootPath);
    const original = loadTopology(base.session.rootPath);
    expect(seeded.components.map((c) => c.id).sort()).toEqual(
      original.components.map((c) => c.id).sort(),
    );
    expect(seeded.controls).toEqual([]);
    expect(seeded.retired).toEqual([]);
  });

  it("refuses to seed a session that already has records", async () => {
    const base = makeCtx();
    await baseline(base);
    expect(() =>
      seedFromBaseline(base.session.rootPath, base.session.rootPath),
    ).toThrow(/already holds records/);
  });
});

describe("update_record", () => {
  it("changes only the given fields, keeps the rest verbatim, and appends the evidence", async () => {
    const ctx = makeCtx();
    await baseline(ctx);
    const before = loadTopology(ctx.session.rootPath).components.find(
      (c) => c.name === "Shop API",
    );
    const result = await run(updateRecord(ctx), {
      kind: "component",
      name: "Shop API",
      changes: { exposure: "private" },
      evidence: [
        {
          source: "source",
          detail: "Port no longer published",
          ref: "docker-compose.yml",
        },
      ],
    });
    expect(result).toMatchObject({ success: true, changed: ["exposure"] });
    const after = loadTopology(ctx.session.rootPath).components.find(
      (c) => c.name === "Shop API",
    );
    expect(after?.exposure).toBe("private");
    expect(after?.atStake).toBe(before?.atStake);
    expect(after?.endpoints).toEqual(before?.endpoints);
    expect(after?.id).toBe(before?.id);
    expect(after?.evidence).toHaveLength(2);
  });

  it("resolves changed references by id, so a later rename still follows", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      const ctx = makeCtx();
      await baseline(ctx);
      await run(documentBoundary(ctx), {
        name: "Public",
        kind: "subnet",
        evidence,
      });
      await run(updateRecord(ctx), {
        kind: "component",
        name: "Shop API",
        changes: { boundary: "Public" },
        evidence,
      });
      vi.advanceTimersByTime(1);
      await run(documentBoundary(ctx), {
        name: "DMZ",
        kind: "subnet",
        renameFrom: "Public",
        evidence,
      });
      expect(
        loadTopology(ctx.session.rootPath).components.find(
          (c) => c.name === "Shop API",
        )?.boundary,
      ).toBe("DMZ");
    } finally {
      vi.useRealTimers();
    }
  });

  it("rejects a field the kind does not have, an unknown reference, and an empty change", async () => {
    const ctx = makeCtx();
    await baseline(ctx);
    expect(
      await run(updateRecord(ctx), {
        kind: "control",
        name: "DB password",
        changes: { endpoints: ["x"] },
        evidence,
      }),
    ).toMatchObject({ error: "invalid_field" });
    expect(
      await run(updateRecord(ctx), {
        kind: "control",
        name: "DB password",
        changes: { appliesTo: ["Redis"] },
        evidence,
      }),
    ).toMatchObject({ error: "unknown_layer" });
    expect(
      await run(updateRecord(ctx), {
        kind: "component",
        name: "Shop API",
        changes: {},
        evidence,
      }),
    ).toMatchObject({ error: "no_changes" });
  });
});

describe("diffTopology", () => {
  it("does not count reformatted endpoints as a change, but does count a different host", async () => {
    const base = makeCtx();
    await baseline(base);
    const next = update(base);
    await run(updateRecord(next), {
      kind: "component",
      name: "Shop API",
      changes: { endpoints: ["app.example:443/"] },
      evidence,
    });
    expect(
      diffTopology(base.session.rootPath, next.session.rootPath, "ses_update")
        .changed,
    ).toEqual([]);
    await run(updateRecord(next), {
      kind: "component",
      name: "Shop API",
      changes: { endpoints: ["https://api.example"] },
      evidence,
    });
    expect(
      diffTopology(
        base.session.rootPath,
        next.session.rootPath,
        "ses_update",
      ).changed.map((c) => Object.keys(c.fields)),
    ).toEqual([["endpoints"]]);
  });

  it("reports added, changed, retired, re-verified, and unverified records — and a rename as a change", async () => {
    const base = makeCtx();
    await baseline(base);
    await run(documentComponent(base), { ...db, name: "Redis", kind: "cache" });
    await run(documentFlow(base), {
      from: "Shop API",
      to: "Redis",
      label: "cache",
      evidence,
    });
    const next = update(base);

    await run(
      documentComponent(next),
      app("Shop API", {
        endpoints: ["https://app.example", "https://api.example"],
      }),
    );
    await run(documentComponent(next), {
      ...db,
      name: "Orders DB",
      renameFrom: "Postgres",
    });
    await run(documentFlow(next), {
      from: "Shop API",
      to: "Orders DB",
      label: "SQL",
      evidence,
    });
    await run(documentComponent(next), { ...db, name: "Jobs", kind: "queue" });
    await run(retireRecord(next), {
      kind: "flow",
      from: "Shop API",
      to: "Redis",
      label: "cache",
      reason: "Cache removed.",
      evidence,
    });
    await run(retireRecord(next), {
      kind: "component",
      name: "Redis",
      reason: "Cache removed.",
      evidence,
    });

    const change = diffTopology(
      base.session.rootPath,
      next.session.rootPath,
      "ses_update",
    );
    const names = (list: { kind: string; name: string }[]) =>
      list.map((c) => `${c.kind}:${c.name}`).sort();
    expect(names(change.added)).toEqual(["component:Jobs"]);
    expect(names(change.retired)).toEqual([
      "component:Redis",
      "flow:Shop API → Redis (cache)",
    ]);
    expect(change.retired.every((r) => r.reason === "Cache removed.")).toBe(
      true,
    );
    // The rename is one change, on the renamed record; the flow and control
    // that point at it still point at the same record.
    expect(
      change.changed.map((c) => [c.name, Object.keys(c.fields).sort()]).sort(),
    ).toEqual([
      ["Orders DB", ["name"]],
      ["Shop API", ["endpoints"]],
    ]);
    expect(names(change.reverified)).toEqual([
      "flow:Shop API → Orders DB (SQL)",
    ]);
    expect(names(change.unverified)).toEqual([
      "boundary:Private",
      "control:DB password",
    ]);
  });

  it("does not count the agent's distinctFrom bookkeeping as a change", async () => {
    const base = makeCtx();
    await baseline(base);
    const next = update(base);
    await run(documentComponent(next), { ...db, distinctFrom: ["Shop API"] });
    const change = diffTopology(
      base.session.rootPath,
      next.session.rootPath,
      "ses_update",
    );
    expect(change.changed).toEqual([]);
    expect(change.reverified.map((r) => r.name)).toEqual(["Postgres"]);
  });

  it("calls a record re-documented with no change re-verified, not changed", async () => {
    const base = makeCtx();
    await baseline(base);
    const next = update(base);
    await run(documentComponent(next), db);
    const change = diffTopology(
      base.session.rootPath,
      next.session.rootPath,
      "ses_update",
    );
    expect(change.changed).toEqual([]);
    expect(change.reverified.map((r) => r.name)).toEqual(["Postgres"]);
    expect(
      readdirSync(join(next.session.rootPath, "topology")).length,
    ).toBeGreaterThan(0);
  });
});
