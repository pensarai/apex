import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApprovalGate,
  ApprovalTimeoutError,
  DEFAULT_DECISION_TIMEOUT_MS,
  INTERNAL_ID_PATTERN,
} from "./approvalGate";
import type { PendingApproval } from "./types";

function expectApprovalId(
  approvalId: PendingApproval["id"] | undefined,
): PendingApproval["id"] {
  expect(approvalId).toBeDefined();
  if (approvalId === undefined) {
    throw new Error("approval-needed event did not fire");
  }
  return approvalId;
}

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
    const assertion =
      expect(pending).rejects.toBeInstanceOf(ApprovalTimeoutError);

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

    let approvalId: PendingApproval["id"] | undefined;
    gate.once("approval-needed", (e) => {
      approvalId = (e as { approval: PendingApproval }).approval.id;
    });

    const pending = gate.check("http_request", "tc_2", { url: "https://t/" });
    expect(approvalId).toBeDefined();

    await vi.advanceTimersByTimeAsync(500);
    gate.approve(expectApprovalId(approvalId));
    await vi.advanceTimersByTimeAsync(1_000);

    await expect(pending).resolves.toBe("approved");
    expect(gate.getActionHistory().at(-1)?.resultSummary).toBeUndefined();
  });

  it("does not fire the timeout when the operator denies in time", async () => {
    const gate = new ApprovalGate({
      requireApproval: true,
      decisionTimeoutMs: 1_000,
    });

    let approvalId: PendingApproval["id"] | undefined;
    gate.once("approval-needed", (e) => {
      approvalId = (e as { approval: PendingApproval }).approval.id;
    });

    const pending = gate.check("http_request", "tc_3", { url: "https://t/" });
    const assertion = expect(pending).rejects.toThrow("Action denied by user");
    await vi.advanceTimersByTimeAsync(500);
    gate.deny(expectApprovalId(approvalId));
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

    let approvalId: PendingApproval["id"] | undefined;
    gate.once("approval-needed", (e) => {
      approvalId = (e as { approval: PendingApproval }).approval.id;
    });

    const pending = gate.check("http_request", "tc_4", { url: "https://t/" });

    // Advance well beyond a "default" timeout — nothing should fire.
    await vi.advanceTimersByTimeAsync(60 * 60 * 1000);
    expect(gate.getPendingApprovals()).toHaveLength(1);

    gate.approve(expectApprovalId(approvalId));
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

describe("ApprovalGate — approval-resolved payload shape", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("includes the full PendingApproval on approve()", async () => {
    const gate = new ApprovalGate({
      requireApproval: true,
      decisionTimeoutMs: 0,
    });

    const resolvedEvents: Array<{
      id: string;
      decision: string;
      approval: PendingApproval;
    }> = [];
    gate.on("approval-resolved", (e) => resolvedEvents.push(e));

    let approvalId: PendingApproval["id"] | undefined;
    gate.once("approval-needed", (e) => {
      approvalId = (e as { approval: PendingApproval }).approval.id;
    });

    const pending = gate.check("execute_command", "tc_payload_1", {
      command: "ffuf -u https://example.com/FUZZ -w wordlist.txt",
      toolCallDescription: "Running ffuf against example.com",
    });

    gate.approve(expectApprovalId(approvalId));
    await expect(pending).resolves.toBe("approved");

    expect(resolvedEvents).toHaveLength(1);
    const [event] = resolvedEvents;
    expect(event.decision).toBe("approved");
    expect(event.approval.toolName).toBe("execute_command");
    expect(event.approval.args.toolCallDescription).toBe(
      "Running ffuf against example.com",
    );
    expect(event.approval.args.command).toBe(
      "ffuf -u https://example.com/FUZZ -w wordlist.txt",
    );
  });

  it("includes the full PendingApproval on deny()", async () => {
    const gate = new ApprovalGate({
      requireApproval: true,
      decisionTimeoutMs: 0,
    });

    const resolvedEvents: Array<{
      id: string;
      decision: string;
      approval: PendingApproval;
    }> = [];
    gate.on("approval-resolved", (e) => resolvedEvents.push(e));

    let approvalId: PendingApproval["id"] | undefined;
    gate.once("approval-needed", (e) => {
      approvalId = (e as { approval: PendingApproval }).approval.id;
    });

    const pending = gate.check("http_request", "tc_payload_2", {
      url: "https://example.com/admin",
    });
    const assertion = expect(pending).rejects.toThrow("Action denied by user");

    gate.deny(expectApprovalId(approvalId));
    await assertion;

    expect(resolvedEvents).toHaveLength(1);
    const [event] = resolvedEvents;
    expect(event.decision).toBe("denied");
    expect(event.approval.toolName).toBe("http_request");
    expect(event.approval.args.url).toBe("https://example.com/admin");
  });

  it("includes the full PendingApproval on timeout", async () => {
    const gate = new ApprovalGate({
      requireApproval: true,
      decisionTimeoutMs: 1_000,
    });

    const resolvedEvents: Array<{
      id: string;
      decision: string;
      approval: PendingApproval;
    }> = [];
    gate.on("approval-resolved", (e) => resolvedEvents.push(e));

    const pending = gate.check("nuclei_scan", "tc_payload_3", {
      target: "https://example.com",
    });
    const assertion =
      expect(pending).rejects.toBeInstanceOf(ApprovalTimeoutError);

    await vi.advanceTimersByTimeAsync(1_000);
    await assertion;

    expect(resolvedEvents).toHaveLength(1);
    const [event] = resolvedEvents;
    expect(event.decision).toBe("denied");
    expect(event.approval.toolName).toBe("nuclei_scan");
    expect(event.approval.args.target).toBe("https://example.com");
  });
});

/**
 * Pin `INTERNAL_ID_PATTERN` to the format the gate actually mints. If anyone
 * changes either side without updating the other, this test fails before the
 * regex silently rots and stops catching leaked correlation IDs in the UI.
 */
describe("ApprovalGate — INTERNAL_ID_PATTERN format-source coupling", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("matches the apr_ IDs minted for pending approvals", async () => {
    const gate = new ApprovalGate({
      requireApproval: true,
      decisionTimeoutMs: 0,
    });

    let approvalId: PendingApproval["id"] | undefined;
    gate.once("approval-needed", (e) => {
      approvalId = (e as { approval: PendingApproval }).approval.id;
    });

    const pending = gate.check("http_request", "tc_pin_1", {});
    const assertion = expect(pending).rejects.toThrow("Action denied by user");

    expect(approvalId).toMatch(INTERNAL_ID_PATTERN);
    expect(expectApprovalId(approvalId).startsWith("apr_")).toBe(true);

    gate.deny(expectApprovalId(approvalId));
    await assertion;
  });

  it("matches the act_ IDs minted for action-history entries", async () => {
    const gate = new ApprovalGate({
      requireApproval: true,
      decisionTimeoutMs: 0,
    });

    let approvalId: PendingApproval["id"] | undefined;
    gate.once("approval-needed", (e) => {
      approvalId = (e as { approval: PendingApproval }).approval.id;
    });

    const pending = gate.check("http_request", "tc_pin_2", {});
    gate.approve(expectApprovalId(approvalId));
    await expect(pending).resolves.toBe("approved");

    const [historyEntry] = gate.getActionHistory();
    expect(historyEntry.id).toMatch(INTERNAL_ID_PATTERN);
    expect(historyEntry.id.startsWith("act_")).toBe(true);
  });
});
