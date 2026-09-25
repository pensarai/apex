import {
  createHttpOastForwarder,
  type RegisteredOastSession,
  type SessionOastRouter,
} from "./oastRouter";
import type {
  SandboxSecurityAttestation,
  SandboxSecurityController,
  SandboxSessionSecurityLease,
  SandboxSessionSecurityRequest,
} from "./sandbox";

export type ProcessEgressEnforcementLease = {
  attestation?: SandboxSecurityAttestation;
  /** Host/control-plane address mapped to the sandbox's reserved listener port. */
  oastListenerBaseUrl?: string;
  environmentVariables?: Record<string, string>;
  dispose(): Promise<void>;
};

/**
 * Platform adapter that owns the actual external privilege boundary (container
 * network, VM firewall, network namespace, or transparent proxy).
 */
export interface ProcessEgressEnforcer {
  enforceSession(
    request: SandboxSessionSecurityRequest,
  ): Promise<ProcessEgressEnforcementLease>;
}

/**
 * Harness-owned composition of process-level egress enforcement and opaque
 * OAST routing. Provider adapters supply only the platform-specific boundary.
 */
export class HarnessSandboxSecurityController
  implements SandboxSecurityController
{
  constructor(
    private readonly enforcer: ProcessEgressEnforcer,
    private readonly oastRouter: SessionOastRouter,
  ) {}

  async provisionSession(
    request: SandboxSessionSecurityRequest,
  ): Promise<SandboxSessionSecurityLease> {
    const enforcement = await this.enforcer.enforceSession(request);
    let oast: RegisteredOastSession | undefined;
    try {
      if (request.oast) {
        if (!enforcement.oastListenerBaseUrl) {
          throw new Error(
            "Process egress enforcer did not expose the reserved OAST listener port",
          );
        }
        oast = await this.oastRouter.registerSession({
          sessionId: request.sessionId,
          eventsPath: request.oast.eventsPath,
          callbackPort: request.oast.callbackPort,
          forward: createHttpOastForwarder(enforcement.oastListenerBaseUrl),
        });
      }

      let disposed = false;
      return {
        attestation: enforcement.attestation,
        oast,
        environmentVariables: enforcement.environmentVariables,
        dispose: async () => {
          if (disposed) return;
          disposed = true;
          try {
            await oast?.dispose();
          } finally {
            await enforcement.dispose();
          }
        },
      };
    } catch (error) {
      await oast?.dispose().catch(() => {});
      await enforcement.dispose().catch(() => {});
      throw error;
    }
  }
}
