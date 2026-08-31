import { describe, expect, it } from "vitest";
import { isAttemptId, isIdempotencyKey } from "../id/id";
import {
  allocateAttemptIdentity,
  type ProviderAttemptEnvelope,
  ProviderAttemptValidationError,
  parseProviderAttemptEnvelope,
  startProviderAttempt,
  UNKNOWN_TOKENS,
} from "./index";

const REQUESTED = {
  provider: "anthropic",
  modelId: "claude-haiku-4-5",
  transport: "anthropic-messages" as const,
};

function start() {
  return startProviderAttempt({
    operationKind: "agent.stream",
    requested: REQUESTED,
    attribution: {
      sessionId: "ses_test",
      runId: "run_test",
      agentId: "root",
    },
  });
}

const FORBIDDEN_KEY =
  /cost|price|rate|usd|billing|customer|account|invoice|ledger/i;

function collectKeys(value: unknown, keys: string[] = []): string[] {
  if (value && typeof value === "object") {
    for (const [key, nested] of Object.entries(value)) {
      keys.push(key);
      collectKeys(nested, keys);
    }
  }
  return keys;
}

describe("allocateAttemptIdentity", () => {
  it("mints distinct opaque attempt and idempotency ids", () => {
    const first = allocateAttemptIdentity();
    const second = allocateAttemptIdentity();
    expect(isAttemptId(first.attemptId)).toBe(true);
    expect(isIdempotencyKey(first.idempotencyKey)).toBe(true);
    expect(first.attemptId).not.toBe(first.idempotencyKey);
    expect(first.attemptId).not.toBe(second.attemptId);
    expect(first.idempotencyKey).not.toBe(second.idempotencyKey);
  });
});

describe("startProviderAttempt", () => {
  it("exposes identity before any provider usage is attached", () => {
    const handle = start();
    expect(isAttemptId(handle.attemptId)).toBe(true);
    expect(isIdempotencyKey(handle.idempotencyKey)).toBe(true);
    expect(handle.started.lifecycle).toBe("started");
    expect(handle.started.tokens).toEqual(UNKNOWN_TOKENS);
    expect(handle.started.attemptId).toBe(handle.attemptId);
    expect(handle.started.attribution.rootAttemptId).toBe(handle.attemptId);
    expect(handle.started.lineage).toEqual({ sequence: 1 });
  });

  it("completes a preallocated identity with adapter usage", () => {
    const handle = start();
    const completed = handle.complete({
      transport: "anthropic-messages",
      usage: {
        input_tokens: 100,
        output_tokens: 9,
        cache_read_input_tokens: 900,
        cache_creation_input_tokens: 0,
      },
    });
    expect(completed.attemptId).toBe(handle.attemptId);
    expect(completed.idempotencyKey).toBe(handle.idempotencyKey);
    expect(completed.lifecycle).toBe("completed");
    expect(completed.tokens).toEqual({
      inclusiveInput: 1000,
      uncachedInput: 100,
      cacheRead: 900,
      cacheWrite: 0,
      output: 9,
    });
  });

  it("keeps reported zero distinct from unknown", () => {
    const handle = start();
    const withZero = handle.complete({
      tokens: {
        inclusiveInput: 10,
        uncachedInput: 10,
        cacheRead: 0,
        cacheWrite: 0,
        output: 1,
      },
    });
    const unknown = handle.fail();
    expect(withZero.tokens.cacheRead).toBe(0);
    expect(unknown.tokens.cacheRead).toBeNull();
    expect(withZero.tokens.cacheRead).not.toBe(unknown.tokens.cacheRead);
  });

  it("records retry lineage on a new identity", () => {
    const first = start();
    const failed = first.fail();
    const retry = first.retry();
    const completed = retry.complete({
      tokens: {
        inclusiveInput: 4,
        uncachedInput: 4,
        cacheRead: 0,
        cacheWrite: 0,
        output: 1,
      },
    });

    expect(failed.lifecycle).toBe("failed");
    expect(retry.attemptId).not.toBe(first.attemptId);
    expect(retry.idempotencyKey).not.toBe(first.idempotencyKey);
    expect(retry.started.lineage).toEqual({
      sequence: 2,
      previousAttemptId: first.attemptId,
    });
    expect(completed.attribution.rootAttemptId).toBe(
      first.started.attribution.rootAttemptId,
    );
    expect(completed.lifecycle).toBe("completed");
  });

  it("attributes a child attempt to its parent and root", () => {
    const root = start();
    const child = startProviderAttempt({
      operationKind: "context.summarize",
      requested: REQUESTED,
      attribution: {
        parentAttemptId: root.attemptId,
        rootAttemptId: root.attemptId,
        sessionId: "ses_test",
      },
    });
    expect(child.started.attribution.parentAttemptId).toBe(root.attemptId);
    expect(child.started.attribution.rootAttemptId).toBe(root.attemptId);
    expect(child.attemptId).not.toBe(root.attemptId);
  });
});

describe("parseProviderAttemptEnvelope", () => {
  it("rejects a first attempt that names a previous id", () => {
    const handle = start();
    const raw = {
      ...handle.started,
      lineage: { sequence: 1, previousAttemptId: handle.attemptId },
    };
    expect(() => parseProviderAttemptEnvelope(raw)).toThrow(
      ProviderAttemptValidationError,
    );
  });

  it("rejects money-shaped fields on the envelope", () => {
    const handle = start();
    expect(() =>
      parseProviderAttemptEnvelope({
        ...handle.started,
        costUsd: 0.12,
      }),
    ).toThrow(ProviderAttemptValidationError);
  });
});

describe("envelope money-free contract", () => {
  it("serialized attempts expose no money or account keys", () => {
    const envelope: ProviderAttemptEnvelope = start().complete({
      transport: "anthropic-messages",
      usage: {
        input_tokens: 10,
        output_tokens: 2,
        cache_read_input_tokens: 0,
        cache_creation_input_tokens: 0,
      },
      providerRequestId: "msg_safe",
      cacheTtlSeconds: 300,
      cacheBreakpoint: "anthropic.cacheControl",
    });
    for (const key of collectKeys(envelope)) {
      expect(key).not.toMatch(FORBIDDEN_KEY);
    }
  });
});
