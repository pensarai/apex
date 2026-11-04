import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { SessionInfo } from "../../../session";
import { inProcessSubagentSpawner } from "../subagentSpawner";
import {
  applyEntraSignInError,
  completeAuthentication,
} from "./completeAuthentication";
import type { ToolContext } from "./types";

const roots: string[] = [];

function makeCtx(): ToolContext {
  const rootPath = mkdtempSync(join(tmpdir(), "complete-auth-"));
  roots.push(rootPath);
  return {
    subagentSpawner: inProcessSubagentSpawner,
    session: { id: "ses_test", rootPath } as SessionInfo,
    agentCwd: rootPath,
    target: "https://app.example",
  };
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true });
});

const signedIn = {
  success: true,
  summary: "Signed in.",
  exportedCookies: "session=abc",
  exportedHeaders: { Authorization: "Bearer abc" },
  strategy: "browser",
  toolCallDescription: "finish",
};

describe("applyEntraSignInError", () => {
  it("leaves the result alone when no Entra error code is given", () => {
    expect(applyEntraSignInError(signedIn)).toEqual(signedIn);
  });

  it("records a failed sign-in even when the model claimed success", () => {
    const result = applyEntraSignInError({
      ...signedIn,
      summary: "Policy page shown.",
      entraErrorCode: "AADSTS53003",
    });

    expect(result.success).toBe(false);
    expect(result.exportedCookies).toBe("");
    expect(result.exportedHeaders).toEqual({});
    expect(result.summary).toBe(
      "Entra sign-in failed (AADSTS53003): Blocked by Conditional Access. Policy page shown.",
    );
    expect(result.authBarrier).toEqual({
      type: "unknown",
      details: "AADSTS53003: Blocked by Conditional Access",
    });
  });

  it("replaces a model-chosen barrier with the one for the code", () => {
    const result = applyEntraSignInError({
      success: false,
      summary: "Stuck.",
      authBarrier: { type: "captcha", details: "guess" },
      entraErrorCode: "AADSTS50076",
      toolCallDescription: "finish",
    });

    expect(result.authBarrier).toEqual({
      type: "mfa",
      details:
        "AADSTS50076: MFA required and no supported method was completed",
    });
  });
});

describe("complete_authentication", () => {
  it("rejects an Entra error code that is not an AADSTS code", () => {
    const tool = completeAuthentication(makeCtx());
    const parsed = (
      tool.inputSchema as { safeParse: (v: unknown) => { success: boolean } }
    ).safeParse({
      ...signedIn,
      entraErrorCode: "Conditional Access",
    });

    expect(parsed.success).toBe(false);
  });

  it("persists the classified failure for downstream agents", async () => {
    const ctx = makeCtx();
    const tool = completeAuthentication(ctx);

    const output = await tool.execute?.(
      { ...signedIn, entraErrorCode: "AADSTS53000" },
      { toolCallId: "call_1", messages: [] },
    );

    const persisted = JSON.parse(
      readFileSync(
        join(ctx.session.rootPath, "auth", "auth-data.json"),
        "utf8",
      ),
    );
    expect(persisted.authenticated).toBe(false);
    expect(persisted.cookies).toBe("");
    expect(persisted.authBarrier.details).toBe(
      "AADSTS53000: Blocked by Conditional Access: compliant device required",
    );
    expect(output).toMatchObject({
      success: false,
      message:
        "Authentication failed. Barrier: unknown — AADSTS53000: Blocked by Conditional Access: compliant device required",
    });
  });
});
