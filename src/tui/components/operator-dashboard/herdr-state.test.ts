import { describe, expect, it } from "vitest";
import {
  buildHerdrSnapshot,
  buildHomeHerdrReport,
  type HerdrDashboardSnapshot,
} from "./herdr-state";

const ready: HerdrDashboardSnapshot = {
  status: "idle",
  loading: false,
  pendingApprovalCount: 0,
  hasPendingQuestions: false,
  planReviewPending: false,
  sessionId: "ses_123",
  modelId: "anthropic/claude-sonnet-4",
  obfuscateEnabled: false,
};

describe("buildHerdrSnapshot", () => {
  it("reports working while the session is still loading", () => {
    const report = buildHerdrSnapshot({
      ...ready,
      loading: true,
      sessionId: null,
    });

    expect(report.state).toBe("working");
    expect(report.message).toBeUndefined();
  });

  it("reports working while the agent executes a turn", () => {
    const report = buildHerdrSnapshot({ ...ready, status: "running" });

    expect(report.state).toBe("working");
  });

  it("reports idle once a new dashboard is ready with no session yet", () => {
    const report = buildHerdrSnapshot({ ...ready, sessionId: null });

    expect(report.state).toBe("idle");
    expect(report.session?.resumeArgv).toEqual(["pensar"]);
    expect(report.session?.id).toBeUndefined();
  });

  it("reports idle after errors, aborts, and completed runs", () => {
    for (const status of ["idle", "done"] as const) {
      expect(buildHerdrSnapshot({ ...ready, status }).state).toBe("idle");
    }
  });

  it("reports blocked while tool approvals are queued", () => {
    const report = buildHerdrSnapshot({
      ...ready,
      status: "waiting",
      pendingApprovalCount: 2,
    });

    expect(report.state).toBe("blocked");
    expect(report.message).toBe("Waiting for tool approval (2 queued)");
  });

  it("reports blocked while user questions are pending", () => {
    const report = buildHerdrSnapshot({
      ...ready,
      status: "waiting",
      hasPendingQuestions: true,
    });

    expect(report.state).toBe("blocked");
    expect(report.message).toBe("Waiting for answers");
  });

  it("reports blocked while a plan awaits review even though the turn ended", () => {
    const report = buildHerdrSnapshot({ ...ready, planReviewPending: true });

    expect(report.state).toBe("blocked");
    expect(report.message).toBe("Waiting for plan review");
  });

  it("keeps blocked when a decision arrives mid-run", () => {
    const report = buildHerdrSnapshot({
      ...ready,
      status: "running",
      pendingApprovalCount: 1,
    });

    expect(report.state).toBe("blocked");
  });
});

describe("buildHerdrSnapshot resume argv", () => {
  it("resumes the session with its model baked in", () => {
    const report = buildHerdrSnapshot(ready);

    expect(report.session).toEqual({
      id: "ses_123",
      resumeArgv: [
        "pensar",
        "--resume",
        "ses_123",
        "--model",
        "anthropic/claude-sonnet-4",
      ],
    });
  });

  it("keeps the resume argv fresh when the model changes", () => {
    const before = buildHerdrSnapshot(ready);
    const after = buildHerdrSnapshot({ ...ready, modelId: "openai/gpt-5" });

    expect(after.session?.resumeArgv).not.toEqual(before.session?.resumeArgv);
    expect(after.session?.resumeArgv).toContain("openai/gpt-5");
  });

  it("keeps the resume argv fresh when the session switches", () => {
    const after = buildHerdrSnapshot({ ...ready, sessionId: "ses_456" });

    expect(after.session?.id).toBe("ses_456");
    expect(after.session?.resumeArgv).toContain("ses_456");
  });

  it("appends --obfuscate when redaction is active so restored output stays redacted", () => {
    const report = buildHerdrSnapshot({ ...ready, obfuscateEnabled: true });

    expect(report.session?.resumeArgv).toEqual([
      "pensar",
      "--resume",
      "ses_123",
      "--model",
      "anthropic/claude-sonnet-4",
      "--obfuscate",
    ]);
  });

  it("omits --model when the model is unknown rather than inventing one", () => {
    const report = buildHerdrSnapshot({ ...ready, modelId: null });

    expect(report.session?.resumeArgv).toEqual([
      "pensar",
      "--resume",
      "ses_123",
    ]);
  });
});

describe("buildHomeHerdrReport", () => {
  it("resets the pane to a plain pensar launch without a session id", () => {
    const report = buildHomeHerdrReport(false);

    expect(report).toEqual({
      state: "idle",
      session: { resumeArgv: ["pensar"] },
    });
    expect(report.session?.id).toBeUndefined();
  });

  it("preserves --obfuscate for the home launch", () => {
    const report = buildHomeHerdrReport(true);

    expect(report.session?.resumeArgv).toEqual(["pensar", "--obfuscate"]);
  });
});
