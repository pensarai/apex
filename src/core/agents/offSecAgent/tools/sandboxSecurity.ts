import { createHash } from "node:crypto";
import { join } from "node:path";
import { parseTargetUrl } from "../../../../util/url";
import type { SessionInfo } from "../../../session";
import { resolveExecutionPolicy } from "./executionPolicy";
import type {
  SandboxAllowedDestination,
  SandboxExecuteOptions,
  SandboxExecutionResult,
  SandboxSessionSecurityLease,
  SandboxSessionSecurityRequest,
  UnifiedSandbox,
} from "./sandbox";
import { getRegistrableDomain } from "./scopeGuard";

const CALLBACK_URL_ENV = "APEX_CALLBACK_URL";
const CALLBACK_PORT_ENV = "APEX_CALLBACK_PORT";
const CALLBACK_EVENTS_ENV = "APEX_CALLBACK_EVENTS_PATH";
const OAST_URL_ENV = "APEX_OAST_HTTP_BASE_URL";
const OAST_PORT_ENV = "APEX_OAST_HTTP_PORT";

function inferTargetPort(target: string, explicitPort?: number): number {
  if (explicitPort) return explicitPort;
  return target.trim().toLowerCase().startsWith("http://") ? 80 : 443;
}

function deriveAllowedDestinations(
  session: SessionInfo,
  target?: string,
): SandboxAllowedDestination[] {
  const destinations = new Map<
    string,
    { ports: Set<number>; includeSubdomains: boolean }
  >();
  const add = (host: string, ports: number[], includeSubdomains: boolean) => {
    const normalized = host.trim().toLowerCase();
    if (!normalized) return;
    const current = destinations.get(normalized) ?? {
      ports: new Set<number>(),
      includeSubdomains,
    };
    for (const port of ports) current.ports.add(port);
    current.includeSubdomains ||= includeSubdomains;
    destinations.set(normalized, current);
  };

  const targets = new Set([
    ...(session.targets ?? []),
    ...(target ? [target] : []),
  ]);
  const targetPorts = new Set<number>();
  for (const value of targets) {
    const parsed = parseTargetUrl(value);
    if (!parsed) continue;
    const port = inferTargetPort(value, parsed.port);
    targetPorts.add(port);
    add(getRegistrableDomain(parsed.hostname), [port], true);
  }

  const configuredPorts = session.config?.scopeConstraints?.allowedPorts ?? [];
  const fallbackPorts = [...new Set([...targetPorts, ...configuredPorts])];
  if (fallbackPorts.length === 0) fallbackPorts.push(80, 443);
  for (const [host, destination] of destinations) {
    add(host, fallbackPorts, destination.includeSubdomains);
  }
  for (const host of session.config?.scopeConstraints?.allowedHosts ?? []) {
    add(host, fallbackPorts, true);
  }

  return [...destinations.entries()]
    .map(([host, value]) => ({
      host,
      ports: [...value.ports].sort((a, b) => a - b),
      includeSubdomains: value.includeSubdomains,
    }))
    .sort((a, b) => a.host.localeCompare(b.host));
}

function policyIdFor(
  request: Omit<SandboxSessionSecurityRequest, "policyId">,
): string {
  return createHash("sha256")
    .update(JSON.stringify(request))
    .digest("hex")
    .slice(0, 24);
}

export function buildSandboxSessionSecurityRequest(
  session: SessionInfo,
  target?: string,
): SandboxSessionSecurityRequest | undefined {
  const config = session.config?.networkSecurity;
  const strict = config?.egress === "strict";
  const oastEnabled = config?.oast?.enabled === true;
  if (!strict && !oastEnabled) return undefined;

  const requestWithoutId: Omit<SandboxSessionSecurityRequest, "policyId"> = {
    sessionId: session.id,
    defaultDeny: strict,
    allowDns: config?.allowDns ?? true,
    allowedDestinations: deriveAllowedDestinations(session, target),
    executionPolicy: (() => {
      const policy = resolveExecutionPolicy(session);
      return {
        destructiveAllowed: policy.destructive.allowed,
        rateLimitTestingAllowed: policy.traffic.rateLimitTestingAllowed,
        availabilityImpactAllowed: policy.traffic.availabilityImpactAllowed,
        requestsPerSecond: policy.traffic.requestsPerSecond,
        burst: policy.traffic.burst,
        maxConcurrency: policy.traffic.maxConcurrency,
      };
    })(),
    ...(oastEnabled
      ? {
          oast: {
            callbackPort: config?.oast?.callbackPort ?? 4000,
            eventsPath: join(session.rootPath, "oast", "requests.jsonl"),
          },
        }
      : {}),
  };
  return {
    ...requestWithoutId,
    policyId: policyIdFor(requestWithoutId),
  };
}

function validateLease(
  request: SandboxSessionSecurityRequest,
  lease: SandboxSessionSecurityLease,
): void {
  if (request.defaultDeny) {
    const attestation = lease.attestation;
    if (
      !attestation ||
      attestation.policyId !== request.policyId ||
      !attestation.defaultDeny ||
      !attestation.coversProcessTree
    ) {
      throw new Error(
        "Sandbox security controller did not attest default-deny process-tree egress for the requested policy",
      );
    }
  }

  if (request.oast) {
    if (!lease.oast) {
      throw new Error(
        "Sandbox security controller did not provision OAST routing",
      );
    }
    if (lease.oast.callbackPort !== request.oast.callbackPort) {
      throw new Error(
        "Sandbox OAST listener port does not match the requested port",
      );
    }
    const callback = new URL(lease.oast.callbackUrl);
    if (callback.protocol !== "http:" && callback.protocol !== "https:") {
      throw new Error("Sandbox OAST callback URL must use HTTP or HTTPS");
    }
  }
}

function environmentForLease(
  lease: SandboxSessionSecurityLease,
): Record<string, string> {
  return {
    ...lease.environmentVariables,
    ...(lease.oast
      ? {
          [CALLBACK_URL_ENV]: lease.oast.callbackUrl,
          [CALLBACK_PORT_ENV]: String(lease.oast.callbackPort),
          [CALLBACK_EVENTS_ENV]: lease.oast.eventsPath,
          [OAST_URL_ENV]: lease.oast.callbackUrl,
          [OAST_PORT_ENV]: String(lease.oast.callbackPort),
        }
      : {}),
  };
}

export class SandboxSessionSecurity {
  public readonly sandbox: UnifiedSandbox;
  public readonly ready: Promise<SandboxSessionSecurityLease>;
  private references = 1;
  private disposed = false;

  constructor(
    sandbox: UnifiedSandbox,
    public readonly request: SandboxSessionSecurityRequest,
    private readonly onFinalDispose?: () => void,
  ) {
    const controller = sandbox.securityController;
    if (!controller) {
      throw new Error(
        "This session requires sandbox network security, but the sandbox has no trusted securityController",
      );
    }

    this.ready = controller.provisionSession(request).then(async (lease) => {
      try {
        validateLease(request, lease);
        return lease;
      } catch (error) {
        await lease.dispose().catch(() => {});
        throw error;
      }
    });
    // A tool call or dispose() will observe the rejection. Attach a handler now
    // so delayed model startup cannot produce an unhandled rejection.
    this.ready.catch(() => {});

    this.sandbox = {
      type: sandbox.type,
      execute: async (
        command: string,
        options: SandboxExecuteOptions = {},
      ): Promise<SandboxExecutionResult> => {
        const lease = await this.ready;
        return sandbox.execute(command, {
          ...options,
          envVars: {
            ...options.envVars,
            ...environmentForLease(lease),
          },
        });
      },
    };
  }

  acquire(): this {
    if (this.disposed) {
      throw new Error("Cannot acquire a disposed sandbox security session");
    }
    this.references += 1;
    return this;
  }

  async dispose(): Promise<void> {
    if (this.disposed) return;
    this.references -= 1;
    if (this.references > 0) return;
    this.disposed = true;
    const lease = await this.ready.catch(() => undefined);
    try {
      await lease?.dispose();
    } finally {
      this.onFinalDispose?.();
    }
  }
}

const sharedSecuritySessions = new WeakMap<
  UnifiedSandbox,
  Map<string, SandboxSessionSecurity>
>();
const inheritedSecuritySessions = new WeakMap<
  UnifiedSandbox,
  SandboxSessionSecurity
>();

export function createSandboxSessionSecurity(
  sandbox: UnifiedSandbox | undefined,
  session: SessionInfo,
  target?: string,
): SandboxSessionSecurity | undefined {
  const request = buildSandboxSessionSecurityRequest(session, target);
  if (!request) return undefined;
  if (!sandbox) {
    throw new Error(
      "This session requires sandbox network security, but no sandbox was provided",
    );
  }

  // Sub-agents receive the already-wrapped sandbox through their tool context.
  // Reuse its controller lease instead of trying to provision a nested policy.
  const inherited = inheritedSecuritySessions.get(sandbox);
  if (inherited?.request.policyId === request.policyId) {
    return inherited.acquire();
  }

  let sessions = sharedSecuritySessions.get(sandbox);
  if (!sessions) {
    sessions = new Map();
    sharedSecuritySessions.set(sandbox, sessions);
  }
  const existing = sessions.get(request.policyId);
  if (existing) return existing.acquire();

  let security: SandboxSessionSecurity;
  security = new SandboxSessionSecurity(sandbox, request, () => {
    sessions?.delete(request.policyId);
    inheritedSecuritySessions.delete(security.sandbox);
  });
  sessions.set(request.policyId, security);
  inheritedSecuritySessions.set(security.sandbox, security);
  return security;
}

export function buildSandboxSecurityPrompt(session: SessionInfo): string {
  const config = session.config?.networkSecurity;
  if (!config?.oast?.enabled) return "";
  return `

## Session callback routing

Apex has provisioned an isolated callback route for this session. The shell environment contains ${CALLBACK_URL_ENV}, ${CALLBACK_PORT_ENV}, and ${CALLBACK_EVENTS_ENV}. Write and launch your own listener on the reserved port, use the opaque callback URL in payloads, and correlate received requests yourself. Do not use third-party callback services.`;
}
