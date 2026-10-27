import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { EngagementJournal } from "./engagementJournal";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});
function journal(): EngagementJournal {
  const root = mkdtempSync(join(tmpdir(), "engagement-journal-"));
  roots.push(root);
  return new EngagementJournal(root);
}

describe("engagement journal", () => {
  it("delivers directed messages in order and replays persisted delivery after restart", () => {
    const first = journal();
    const path = roots[0];
    if (!path) throw new Error("Test journal root is missing");
    const a = first.append({
      kind: "mail",
      from: "lead",
      to: "worker",
      text: "first",
    });
    const b = first.append({
      kind: "mail",
      from: "lead",
      to: "worker",
      text: "second",
    });
    expect(
      first.take("worker").map((message) => String(message.content)),
    ).toEqual([
      expect.stringContaining("first"),
      expect.stringContaining("second"),
    ]);
    const restarted = new EngagementJournal(path);
    expect(restarted.pending("worker")).toEqual([]);
    const replay = restarted.resumeMessages("worker", []);
    expect(replay.map((message) => String(message.content))).toEqual([
      expect.stringContaining(a.id),
      expect.stringContaining(b.id),
    ]);
    expect(restarted.resumeMessages("worker", replay)).toEqual(replay);
  });

  it("shares board posts and only wakes listeners for material events", () => {
    const first = journal();
    const events: string[] = [];
    first.onMaterial((event) => events.push(event.kind));
    first.append({ kind: "progress", from: "worker", text: "halfway" });
    first.append({ kind: "board", from: "worker", text: "Reusable token" });
    first.append({
      kind: "help",
      from: "worker",
      text: "Need auth",
      missionId: "m1",
    });
    first.append({
      kind: "completed",
      from: "worker",
      text: "done",
      missionId: "m1",
    });
    expect(events).toEqual(["help", "completed"]);
    const path = roots[0];
    if (!path) throw new Error("Test journal root is missing");
    expect(new EngagementJournal(path).board().entries[0]?.text).toBe(
      "Reusable token",
    );
  });
});
