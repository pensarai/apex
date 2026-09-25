import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { SessionOastRouter } from "./oastRouter";

const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
  await Promise.allSettled(cleanups.splice(0).map((cleanup) => cleanup()));
});

describe("SessionOastRouter", () => {
  it("routes an opaque callback to the reserved listener and persists NDJSON", async () => {
    const received: Array<{ path: string; body: string; requestId?: string }> =
      [];
    const root = await mkdtemp(join(tmpdir(), "apex-oast-"));
    cleanups.push(() => rm(root, { recursive: true, force: true }));
    const eventsPath = join(root, "requests.jsonl");
    const router = new SessionOastRouter({
      externalIngress: true,
      publicBaseUrl: "https://callbacks.example",
    });
    cleanups.push(() => router.close());
    const route = await router.registerSession({
      sessionId: "ses_oast_test",
      eventsPath,
      callbackPort: 4000,
      forward: async (request) => {
        received.push({
          path: request.path,
          body: Buffer.from(request.body).toString("utf8"),
          requestId: request.requestId,
        });
        return { status: 201, body: "listener-ok" };
      },
    });
    cleanups.push(() => route.dispose());

    const response = await router.dispatch({
      url: `${route.callbackUrl}/proof?nonce=abc`,
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: Buffer.from("captured-flag"),
    });

    expect(response.status).toBe(201);
    expect(response.body).toBe("listener-ok");
    expect(received).toHaveLength(1);
    expect(received[0]).toMatchObject({
      path: "/proof?nonce=abc",
      body: "captured-flag",
    });
    expect(received[0]?.requestId).toMatch(/^oast_/);

    const record = JSON.parse((await readFile(eventsPath, "utf8")).trim());
    expect(record).toMatchObject({
      type: "oast-request",
      sessionId: "ses_oast_test",
      method: "POST",
      path: "/proof?nonce=abc",
      forwarded: true,
    });
    expect(Buffer.from(record.bodyBase64, "base64").toString("utf8")).toBe(
      "captured-flag",
    );
  });

  it("records callbacks even when listener delivery fails", async () => {
    const root = await mkdtemp(join(tmpdir(), "apex-oast-failed-"));
    cleanups.push(() => rm(root, { recursive: true, force: true }));
    const eventsPath = join(root, "requests.jsonl");
    const router = new SessionOastRouter({
      externalIngress: true,
      publicBaseUrl: "https://callbacks.example",
    });
    cleanups.push(() => router.close());
    const route = await router.registerSession({
      sessionId: "ses_oast_failed",
      eventsPath,
      callbackPort: 4000,
      forward: async () => {
        throw new Error("listener unavailable");
      },
    });

    const response = await router.dispatch({ url: route.callbackUrl });
    expect(response.status).toBe(202);
    expect(response.headers?.["x-apex-oast-recorded"]).toBe("true");
    const record = JSON.parse((await readFile(eventsPath, "utf8")).trim());
    expect(record).toMatchObject({
      forwarded: false,
      forwardError: "listener unavailable",
    });
  });
});
