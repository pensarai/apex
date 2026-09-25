import { describe, expect, it, vi } from "vitest";
import type { SessionInfo } from "../../../session";
import type { SandboxSessionSecurityRequest, UnifiedSandbox } from "./sandbox";
import {
  buildSandboxSessionSecurityRequest,
  createSandboxSessionSecurity,
} from "./sandboxSecurity";

function session(overrides: Partial<SessionInfo> = {}): SessionInfo {
  return {
    id: "ses_security_test",
    version: "test",
    targets: ["https://api.example.com/path"],
    time: { created: 1, updated: 1 },
    rootPath: "/tmp/session-security-test",
    logsPath: "/tmp/session-security-test/logs",
    findingsPath: "/tmp/session-security-test/findings",
    scratchpadPath: "/tmp/session-security-test/scratchpad",
    pocsPath: "/tmp/session-security-test/pocs",
    config: {
      networkSecurity: {
        egress: "strict",
        oast: { enabled: true, callbackPort: 4000 },
      },
      scopeConstraints: {
        allowedHosts: ["collector.internal"],
        allowedPorts: [8080],
      },
    },
    ...overrides,
  };
}

describe("sandbox session security", () => {
  it("derives a stable default-deny policy from session scope", () => {
    const request = buildSandboxSessionSecurityRequest(session());

    expect(request).toMatchObject({
      defaultDeny: true,
      allowDns: true,
      oast: {
        callbackPort: 4000,
        eventsPath: "/tmp/session-security-test/oast/requests.jsonl",
      },
      executionPolicy: {
        destructiveAllowed: false,
        rateLimitTestingAllowed: false,
        availabilityImpactAllowed: false,
        requestsPerSecond: 50,
        burst: 1,
        maxConcurrency: 4,
      },
    });
    expect(request?.policyId).toMatch(/^[0-9a-f]{24}$/);
    expect(request?.allowedDestinations).toEqual([
      {
        host: "collector.internal",
        ports: [443, 8080],
        includeSubdomains: true,
      },
      { host: "example.com", ports: [443, 8080], includeSubdomains: true },
    ]);
    expect(buildSandboxSessionSecurityRequest(session())).toEqual(request);
  });

  it("fails synchronously when strict security has no trusted controller", () => {
    const sandbox: UnifiedSandbox = {
      type: "linux",
      execute: vi.fn(),
    };
    expect(() => createSandboxSessionSecurity(sandbox, session())).toThrow(
      "no trusted securityController",
    );
  });

  it("fails closed instead of running strict policy in local mode", () => {
    expect(() => createSandboxSessionSecurity(undefined, session())).toThrow(
      "no sandbox was provided",
    );
  });

  it("blocks execution until attestation and injects canonical callback env", async () => {
    let capturedRequest: SandboxSessionSecurityRequest | undefined;
    const execute = vi.fn(async () => ({
      stdout: "ok",
      stderr: "",
      exitCode: 0,
      success: true,
    }));
    const dispose = vi.fn(async () => {});
    const sandbox: UnifiedSandbox = {
      type: "linux",
      execute,
      securityController: {
        provisionSession: async (request) => {
          capturedRequest = request;
          return {
            attestation: {
              policyId: request.policyId,
              controller: "test-controller",
              boundary: "container",
              defaultDeny: true,
              coversProcessTree: true,
            },
            oast: {
              callbackUrl: "https://oast.example/callback/opaque",
              callbackPort: 4000,
              eventsPath: request.oast?.eventsPath ?? "",
            },
            environmentVariables: { CONTROLLER_VALUE: "yes" },
            dispose,
          };
        },
      },
    };

    const security = createSandboxSessionSecurity(sandbox, session());
    await security?.sandbox.execute("env", {
      envVars: { CALL_VALUE: "yes", APEX_CALLBACK_PORT: "9999" },
    });

    expect(capturedRequest?.defaultDeny).toBe(true);
    expect(execute).toHaveBeenCalledWith("env", {
      envVars: {
        CALL_VALUE: "yes",
        CONTROLLER_VALUE: "yes",
        APEX_CALLBACK_URL: "https://oast.example/callback/opaque",
        APEX_CALLBACK_PORT: "4000",
        APEX_CALLBACK_EVENTS_PATH:
          "/tmp/session-security-test/oast/requests.jsonl",
        APEX_OAST_HTTP_BASE_URL: "https://oast.example/callback/opaque",
        APEX_OAST_HTTP_PORT: "4000",
      },
    });
    await security?.dispose();
    expect(dispose).toHaveBeenCalledOnce();
  });

  it("rejects a controller that cannot attest the whole process tree", async () => {
    const sandbox: UnifiedSandbox = {
      type: "linux",
      execute: vi.fn(),
      securityController: {
        provisionSession: async (request) => ({
          attestation: {
            policyId: request.policyId,
            controller: "weak-proxy",
            boundary: "transparent-proxy",
            defaultDeny: true,
            coversProcessTree: false,
          },
          dispose: async () => {},
        }),
      },
    };
    const security = createSandboxSessionSecurity(sandbox, session());

    await expect(security?.sandbox.execute("curl target")).rejects.toThrow(
      "did not attest default-deny process-tree egress",
    );
    await security?.dispose();
  });

  it("reference-counts one controller lease across agents", async () => {
    const provisionSession = vi.fn(
      async (request: SandboxSessionSecurityRequest) => ({
        attestation: {
          policyId: request.policyId,
          controller: "shared",
          boundary: "microvm" as const,
          defaultDeny: true,
          coversProcessTree: true,
        },
        oast: {
          callbackUrl: "https://oast.example/shared",
          callbackPort: 4000,
          eventsPath: request.oast?.eventsPath ?? "",
        },
        dispose: vi.fn(async () => {}),
      }),
    );
    const sandbox: UnifiedSandbox = {
      type: "linux",
      execute: vi.fn(async () => ({
        stdout: "",
        stderr: "",
        exitCode: 0,
        success: true,
      })),
      securityController: { provisionSession },
    };

    const first = createSandboxSessionSecurity(sandbox, session());
    const second = createSandboxSessionSecurity(sandbox, session());
    const inherited = createSandboxSessionSecurity(first?.sandbox, session());
    expect(first).toBe(second);
    expect(first).toBe(inherited);
    await first?.ready;
    expect(provisionSession).toHaveBeenCalledOnce();

    const lease = await first?.ready;
    await first?.dispose();
    expect(lease?.dispose).not.toHaveBeenCalled();
    await second?.dispose();
    expect(lease?.dispose).not.toHaveBeenCalled();
    await inherited?.dispose();
    expect(lease?.dispose).toHaveBeenCalledOnce();
  });
});
