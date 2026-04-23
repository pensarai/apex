import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApprovalGate,
  ApprovalTimeoutError,
  DEFAULT_DECISION_TIMEOUT_MS,
} from "./approvalGate";

describe("ApprovalGate — operator decision timeout", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("denies the pending approval when the operator does not respond within the SLA", async () => {
    const gate = new ApprovalGate({
      requireApproval: true,
      decisionTimeoutMs: 1_000,
    });

    const resolvedEvents: unknown[] = [];
    gate.on("approval-resolved", (e) => resolvedEvents.push(e));

    const pending = gate.check("http_request", "tc_1", { url: "https://t/" });
    // Attach the rejection assertion before advancing timers so the
    // eventual reject() lands on an already-handled promise.
    const assertion = expect(pending).rejects.toBeInstanceOf(
      ApprovalTimeoutError,
    );

    // Operator never responds — advance past the SLA.
    await vi.advanceTimersByTimeAsync(1_000);
    await assertion;

    expect(gate.getPendingApprovals()).toHaveLength(0);
    expect(resolvedEvents).toEqual([
      expect.objectContaining({
        type: "approval-resolved",
        decision: "denied",
      }),
    ]);

    const [historyEntry] = gate.getActionHistory();
    expect(historyEntry.decision).toBe("denied");
    expect(historyEntry.resultSummary).toBe("decision_timeout:1000ms");
  });

  it("does not fire the timeout when the operator approves in time", async () => {
    const gate = new ApprovalGate({
      requireApproval: true,
      decisionTimeoutMs: 1_000,
    });

    let approvalId = "";
    gate.once("approval-needed", (e) => {
      approvalId = (e as { approval: { id: string } }).approval.id;
    });

    const pending = gate.check("http_request", "tc_2", { url: "https://t/" });
    expect(approvalId).not.toBe("");

    await vi.advanceTimersByTimeAsync(500);
    gate.approve(approvalId);
    await vi.advanceTimersByTimeAsync(1_000);

    await expect(pending).resolves.toBe("approved");
    expect(gate.getActionHistory().at(-1)?.resultSummary).toBeUndefined();
  });

  it("does not fire the timeout when the operator denies in time", async () => {
    const gate = new ApprovalGate({
      requireApproval: true,
      decisionTimeoutMs: 1_000,
    });

    let approvalId = "";
    gate.once("approval-needed", (e) => {
      approvalId = (e as { approval: { id: string } }).approval.id;
    });

    const pending = gate.check("http_request", "tc_3", { url: "https://t/" });
    const assertion = expect(pending).rejects.toThrow("Action denied by user");
    await vi.advanceTimersByTimeAsync(500);
    gate.deny(approvalId);
    await vi.advanceTimersByTimeAsync(1_000);

    await assertion;
    expect(gate.getActionHistory().at(-1)?.resultSummary).toBeUndefined();
  });

  it("defaults to a 15-minute SLA when none is supplied", () => {
    expect(DEFAULT_DECISION_TIMEOUT_MS).toBe(15 * 60 * 1000);
    const gate = new ApprovalGate({ requireApproval: true });
    expect(gate.getConfig().decisionTimeoutMs).toBe(
      DEFAULT_DECISION_TIMEOUT_MS,
    );
  });

  it("disables the timeout when decisionTimeoutMs is explicitly undefined-like (0)", async () => {
    const gate = new ApprovalGate({
      requireApproval: true,
      decisionTimeoutMs: 0,
    });

    let approvalId = "";
    gate.once("approval-needed", (e) => {
      approvalId = (e as { approval: { id: string } }).approval.id;
    });

    const pending = gate.check("http_request", "tc_4", { url: "https://t/" });

    // Advance well beyond a "default" timeout — nothing should fire.
    await vi.advanceTimersByTimeAsync(60 * 60 * 1000);
    expect(gate.getPendingApprovals()).toHaveLength(1);

    gate.approve(approvalId);
    await expect(pending).resolves.toBe("approved");
  });

  it("auto-approves without ever starting a timer when requireApproval is false", async () => {
    const gate = new ApprovalGate({
      requireApproval: false,
      decisionTimeoutMs: 1_000,
    });

    const result = await gate.check("http_request", "tc_5", {});
    expect(result).toBe("auto-approved");
    await vi.advanceTimersByTimeAsync(5_000);
    expect(gate.getPendingApprovals()).toHaveLength(0);
  });
});
