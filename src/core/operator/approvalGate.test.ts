import { describe, expect, it, vi } from "vitest";
import {
  ApprovalDeniedError,
  ApprovalGate,
  ApprovalTimeoutError,
  DEFAULT_DECISION_TIMEOUT_MS,
} from "./approvalGate";

describe("ApprovalGate — operator decision timeout", () => {
  const sleep = (ms: number) =>
    new Promise((resolve) => setTimeout(resolve, ms));

  it("denies the pending approval when the operator does not respond within the SLA", async () => {
    const gate = new ApprovalGate({
      requireApproval: true,
      decisionTimeoutMs: 5,
    });

    const resolvedEvents: unknown[] = [];
    gate.on("approval-resolved", (e) => resolvedEvents.push(e));

    const pending = gate.check("http_request", "tc_1", { url: "https://t/" });
    await Promise.resolve();
    // Attach the rejection assertion before advancing timers so the
    // eventual reject() lands on an already-handled promise.
    const assertion =
      expect(pending).rejects.toBeInstanceOf(ApprovalTimeoutError);

    // Operator never responds — advance past the SLA.
    await sleep(10);
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
    expect(historyEntry.resultSummary).toBe("decision_timeout:5ms");
  });

  it("does not fire the timeout when the operator approves in time", async () => {
    const gate = new ApprovalGate({
      requireApproval: true,
      decisionTimeoutMs: 20,
    });

    let approvalId = "";
    gate.once("approval-needed", (e) => {
      approvalId = (e as { approval: { id: string } }).approval.id;
    });

    const pending = gate.check("http_request", "tc_2", { url: "https://t/" });
    await Promise.resolve();
    expect(approvalId).not.toBe("");

    gate.approve(approvalId);
    await sleep(25);

    await expect(pending).resolves.toBe("approved");
    expect(gate.getActionHistory().at(-1)?.resultSummary).toBeUndefined();
  });

  it("does not fire the timeout when the operator denies in time", async () => {
    const gate = new ApprovalGate({
      requireApproval: true,
      decisionTimeoutMs: 20,
    });

    const pending = gate.check("http_request", "tc_3", { url: "https://t/" });
    await Promise.resolve();
    const approvalId = gate.getPendingApprovals()[0]?.id;
    expect(approvalId).toBeTruthy();
    gate.deny(approvalId!);
    const assertion = expect(pending).rejects.toThrow("Action denied by user");
    await sleep(25);

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
    await Promise.resolve();

    // Wait beyond the configured zero timeout — nothing should fire.
    await sleep(5);
    expect(gate.getPendingApprovals()).toHaveLength(1);

    gate.approve(approvalId);
    await expect(pending).resolves.toBe("approved");
  });

  it("auto-approves without ever starting a timer when requireApproval is false", async () => {
    const gate = new ApprovalGate({
      requireApproval: false,
      decisionTimeoutMs: 5,
    });

    const result = await gate.check("http_request", "tc_5", {});
    expect(result).toBe("auto-approved");
    await sleep(10);
    expect(gate.getPendingApprovals()).toHaveLength(0);
  });

  it("populates pending approval classification from the tool classifier", async () => {
    const gate = new ApprovalGate({
      requireApproval: true,
      decisionTimeoutMs: 0,
    });

    const pending = gate.check("execute_command", "tc_tier", {
      command: "gobuster dir -u https://example.com -w words.txt",
    });
    await Promise.resolve();
    const [approval] = gate.getPendingApprovals();

    expect(approval).toMatchObject({
      tier: 4,
      intent: "intrusive",
    });
    expect(approval.reasoning).toContain("intrusive");

    gate.approve(approval.id);
    await expect(pending).resolves.toBe("approved");
    expect(gate.getActionHistory().at(-1)).toMatchObject({
      tier: 4,
      intent: "intrusive",
      decision: "approved",
    });
  });

  it("auto-approves actions at or below the configured threshold", async () => {
    const gate = new ApprovalGate({
      requireApproval: true,
      autoApproveUpToTier: 3,
      decisionTimeoutMs: 1_000,
    });

    await expect(
      gate.check("execute_command", "tc_passive", {
        command: "dig example.com",
      }),
    ).resolves.toBe("auto-approved");

    expect(gate.getPendingApprovals()).toHaveLength(0);
    expect(gate.getActionHistory().at(-1)).toMatchObject({
      tier: 1,
      intent: "passive",
      decision: "auto-approved",
    });
  });

  it("still prompts for actions above the configured threshold", async () => {
    const gate = new ApprovalGate({
      requireApproval: true,
      autoApproveUpToTier: 3,
      decisionTimeoutMs: 0,
    });

    const pending = gate.check("execute_command", "tc_intrusive", {
      command: "ffuf -u https://example.com/FUZZ -w words.txt",
    });
    await Promise.resolve();

    expect(gate.getPendingApprovals()).toHaveLength(1);
    expect(gate.getPendingApprovals()[0]).toMatchObject({
      tier: 4,
      intent: "intrusive",
    });
    gate.approve(gate.getPendingApprovals()[0].id);
    await expect(pending).resolves.toBe("approved");
  });
});

// End-to-end integration: replicate the exact pattern offensiveSecurityAgent
// uses to wrap tools with the gate. This covers the full chain — tool call
// -> wrapper -> gate.check() -> classifier -> policy -> decision -> original
// execute — in one place, so we don't have to open an operator session to
// prove the plumbing works.
describe("ApprovalGate — tool wrapping integration", () => {
  const sleep = (ms: number) =>
    new Promise((resolve) => setTimeout(resolve, ms));

  type Wrapped<T = unknown> = (
    args: Record<string, unknown> & { toolCallId?: string },
  ) => Promise<T | { blocked: true; reason: string }>;

  function wrapTool<T>(
    gate: ApprovalGate,
    toolName: string,
    execute: (args: Record<string, unknown>) => Promise<T>,
  ): Wrapped<T> {
    return async (args) => {
      const toolCallId = String(args.toolCallId ?? `tc_${Date.now()}`);
      const { toolCallId: _ignore, ...toolArgs } = args;
      try {
        await gate.check(toolName, toolCallId, toolArgs);
      } catch (err) {
        if (err instanceof ApprovalDeniedError) {
          return { blocked: true, reason: "Denied by operator" };
        }
        throw err;
      }
      return execute(toolArgs);
    };
  }

  it("auto-approves T1-T3 through the wrapped tool and runs the real execute", async () => {
    const gate = new ApprovalGate({
      requireApproval: true,
      autoApproveUpToTier: 3,
    });
    const execute = vi.fn().mockResolvedValue({ stdout: "ok" });
    const tool = wrapTool(gate, "execute_command", execute);

    const result = await tool({ command: "dig example.com" });

    expect(result).toEqual({ stdout: "ok" });
    expect(execute).toHaveBeenCalledTimes(1);
    expect(execute).toHaveBeenCalledWith({ command: "dig example.com" });
    expect(gate.getActionHistory().at(-1)).toMatchObject({
      tier: 1,
      intent: "passive",
      decision: "auto-approved",
    });
  });

  it("holds T4 actions until the operator approves, then runs execute", async () => {
    const gate = new ApprovalGate({
      requireApproval: true,
      autoApproveUpToTier: 3,
      decisionTimeoutMs: 0,
    });
    const execute = vi.fn().mockResolvedValue({ stdout: "done" });
    const tool = wrapTool(gate, "execute_command", execute);

    const pending = tool({
      command: "ffuf -u https://example.com/FUZZ -w words.txt",
    });
    await Promise.resolve();

    expect(execute).not.toHaveBeenCalled();
    const [approval] = gate.getPendingApprovals();
    expect(approval).toMatchObject({ tier: 4, intent: "intrusive" });

    gate.approve(approval.id);
    await expect(pending).resolves.toEqual({ stdout: "done" });
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it("returns blocked sentinel without running execute when denied", async () => {
    const gate = new ApprovalGate({
      requireApproval: true,
      autoApproveUpToTier: 3,
      decisionTimeoutMs: 0,
    });
    const execute = vi.fn().mockResolvedValue({ stdout: "should not run" });
    const tool = wrapTool(gate, "execute_command", execute);

    const pending = tool({
      command: "nikto -h https://example.com",
    });
    await Promise.resolve();

    const [approval] = gate.getPendingApprovals();
    gate.deny(approval.id);
    await sleep(5);

    await expect(pending).resolves.toEqual({
      blocked: true,
      reason: "Denied by operator",
    });
    expect(execute).not.toHaveBeenCalled();
    expect(gate.getActionHistory().at(-1)).toMatchObject({
      tier: 4,
      intent: "intrusive",
      decision: "denied",
    });
  });
});
