import { rm } from "node:fs/promises";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HarnessSandboxSecurityController } from "./harnessSandboxSecurityController";
import { SessionOastRouter } from "./oastRouter";
import type { SandboxSessionSecurityRequest } from "./sandbox";

const originalFetch = globalThis.fetch;

afterEach(async () => {
  globalThis.fetch = originalFetch;
  await Promise.all([
    rm("/tmp/controller-oast-events.jsonl", { force: true }),
    rm("/tmp/missing-mapping.jsonl", { force: true }),
  ]);
});

describe("HarnessSandboxSecurityController", () => {
  it("composes external process enforcement with session OAST forwarding", async () => {
    const disposeEnforcement = vi.fn(async () => {});
    const request: SandboxSessionSecurityRequest = {
      sessionId: "ses_controller_test",
      policyId: "policy-controller-test",
      defaultDeny: true,
      allowDns: true,
      allowedDestinations: [
        {
          host: "example.com",
          ports: [443],
          includeSubdomains: true,
        },
      ],
      oast: {
        callbackPort: 4000,
        eventsPath: "/tmp/controller-oast-events.jsonl",
      },
    };
    const enforcer = {
      enforceSession: vi.fn(async () => ({
        attestation: {
          policyId: request.policyId,
          controller: "container-network",
          boundary: "container" as const,
          defaultDeny: true,
          coversProcessTree: true,
        },
        oastListenerBaseUrl: "http://agent-listener.internal:4000",
        dispose: disposeEnforcement,
      })),
    };
    const fetchMock = vi.fn(
      async () =>
        new Response("listener-response", {
          status: 202,
          headers: { "content-type": "text/plain" },
        }),
    );
    globalThis.fetch = fetchMock as unknown as typeof originalFetch;
    const router = new SessionOastRouter({
      externalIngress: true,
      publicBaseUrl: "https://callbacks.example",
    });
    const controller = new HarnessSandboxSecurityController(enforcer, router);

    const lease = await controller.provisionSession(request);
    const result = await router.dispatch({
      url: `${lease.oast?.callbackUrl}/proof`,
      method: "POST",
      body: Buffer.from("proof-body"),
    });

    expect(enforcer.enforceSession).toHaveBeenCalledWith(request);
    expect(fetchMock).toHaveBeenCalledOnce();
    const calls = fetchMock.mock.calls as unknown as Array<
      [string | URL | Request, RequestInit?]
    >;
    const [url, init] = calls[0] ?? [];
    expect(url).toBe("http://agent-listener.internal:4000/proof");
    expect(init?.method).toBe("POST");
    expect(result).toMatchObject({ status: 202 });

    await lease.dispose();
    expect(disposeEnforcement).toHaveBeenCalledOnce();
    expect(
      await router.dispatch({ url: lease.oast?.callbackUrl ?? "" }),
    ).toMatchObject({ status: 404 });
    await router.close();
  });

  it("tears down enforcement when OAST listener mapping is missing", async () => {
    const dispose = vi.fn(async () => {});
    const router = new SessionOastRouter({
      externalIngress: true,
      publicBaseUrl: "https://callbacks.example",
    });
    const controller = new HarnessSandboxSecurityController(
      {
        enforceSession: async () => ({ dispose }),
      },
      router,
    );

    await expect(
      controller.provisionSession({
        sessionId: "ses_missing_mapping",
        policyId: "policy-missing-mapping",
        defaultDeny: false,
        allowDns: true,
        allowedDestinations: [],
        oast: {
          callbackPort: 4000,
          eventsPath: "/tmp/missing-mapping.jsonl",
        },
      }),
    ).rejects.toThrow("did not expose the reserved OAST listener port");
    expect(dispose).toHaveBeenCalledOnce();
    await router.close();
  });
});
