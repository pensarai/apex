import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CredentialManager } from "../../../credentials";
import type { SessionInfo } from "../../../session";
import {
  type AttackSurfaceAgentInput,
  blackboxAttackSurfaceDefinition,
  buildBlackboxPrompt,
} from "./blackboxAgent";

describe("buildBlackboxPrompt", () => {
  it("guides SMS MFA without exposing the shared number", () => {
    const credentialManager = new CredentialManager();
    credentialManager.add({
      username: "tester",
      password: "secret",
      loginUrl: "https://example.com/login",
      additionalFields: {
        authMethod: "sms-mfa",
        phoneNumber: "stage-managed-number",
      },
    });

    const prompt = buildBlackboxPrompt("https://example.com", {
      id: "session-1",
      rootPath: "/tmp/apex-blackbox-prompt",
      config: {},
      credentialManager,
    } as SessionInfo);

    expect(prompt).toContain("Authentication method: sms-mfa");
    expect(prompt).toContain("`sms-mfa`: fill username and password first");
    expect(prompt).toContain("Make at most two separate reservation attempts");
    expect(prompt).not.toContain("stage-managed-number");
  });
});

const stepRoots: string[] = [];
afterEach(() => {
  for (const root of stepRoots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

type StepEvent = Parameters<
  NonNullable<AttackSurfaceAgentInput["onStepFinish"]>
>[0];
const stepEvent = { response: { messages: [] } } as unknown as StepEvent;

function stepHandler(onStepFinish?: AttackSurfaceAgentInput["onStepFinish"]) {
  const rootPath = mkdtempSync(join(tmpdir(), "blackbox-step-finish-"));
  stepRoots.push(rootPath);
  const opts = {
    target: "https://example.com",
    model: "test-model",
    session: { rootPath, config: {} } as SessionInfo,
    onStepFinish,
  } as AttackSurfaceAgentInput;
  const { createState, onStepFinish: createHandler } =
    blackboxAttackSurfaceDefinition;
  assert(createState && createHandler);
  const finish = createHandler(opts, createState(opts));
  assert(finish, "blackbox step-finish handler must be defined");
  return {
    finish,
    logPath: join(
      rootPath,
      "subagents",
      "attack-surface-agent",
      "attack-surface-agent.log",
    ),
  };
}

describe("blackbox specialized step callback", () => {
  it("waits for the caller's async step effect before finishing the step", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const { finish, logPath } = stepHandler(() => gate);
    let settled = false;
    const pending = Promise.resolve(finish(stepEvent)).then(() => {
      settled = true;
    });
    try {
      await Promise.resolve();
      expect(settled).toBe(false);
    } finally {
      release();
      await pending;
    }
    expect(JSON.parse(readFileSync(logPath, "utf8"))).toEqual([]);
  });
  it("propagates the original callback failure without writing a success log", async () => {
    const failure = new Error("surface persistence failed");
    const { finish, logPath } = stepHandler(async () => {
      throw failure;
    });
    await expect(finish(stepEvent)).rejects.toBe(failure);
    expect(existsSync(logPath)).toBe(false);
  });

  it("preserves cancellation while waiting for the callback", async () => {
    const controller = new AbortController();
    const failure = new DOMException("cancelled", "AbortError");
    const { finish, logPath } = stepHandler(
      () =>
        new Promise<void>((_resolve, reject) => {
          controller.signal.addEventListener(
            "abort",
            () => reject(controller.signal.reason),
            { once: true },
          );
        }),
    );
    const pending = finish(stepEvent);
    controller.abort(failure);
    await expect(pending).rejects.toBe(failure);
    expect(existsSync(logPath)).toBe(false);
  });

  it("still writes step messages when no callback is configured", async () => {
    const { finish, logPath } = stepHandler();
    await finish(stepEvent);
    expect(JSON.parse(readFileSync(logPath, "utf8"))).toEqual([]);
  });
});
