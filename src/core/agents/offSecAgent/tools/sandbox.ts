/**
 * Minimal sandbox interface consumed by apex tools.
 *
 * `ConsoleSandbox` from `@console/sandbox` structurally satisfies this
 * interface, so callers can pass it directly:
 *
 * @example
 * ```ts
 * const sandbox = await createSandbox({ image, type: 'linux' });
 * // sandbox satisfies UnifiedSandbox
 * ```
 */

export type SandboxType = "linux" | "windows";

export interface SandboxExecuteOptions {
  cwd?: string;
  envVars?: Record<string, string>;
  timeout?: number;
  retries?: number;
}

export interface SandboxExecutionResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  success: boolean;
}

export type SandboxAllowedDestination = {
  host: string;
  ports: number[];
  includeSubdomains: boolean;
};

export type SandboxOastRequest = {
  callbackPort: number;
  eventsPath: string;
};

export type SandboxSessionSecurityRequest = {
  sessionId: string;
  policyId: string;
  defaultDeny: boolean;
  allowDns: boolean;
  allowedDestinations: SandboxAllowedDestination[];
  executionPolicy: {
    destructiveAllowed: boolean;
    rateLimitTestingAllowed: boolean;
    availabilityImpactAllowed: false;
    requestsPerSecond: number;
    burst: number;
    maxConcurrency: number;
  };
  oast?: SandboxOastRequest;
};

export type SandboxSecurityAttestation = {
  policyId: string;
  controller: string;
  boundary:
    | "network-namespace"
    | "container"
    | "microvm"
    | "host-firewall"
    | "transparent-proxy";
  defaultDeny: boolean;
  coversProcessTree: boolean;
};

export type SandboxOastLease = {
  callbackUrl: string;
  callbackPort: number;
  eventsPath: string;
};

export interface SandboxSessionSecurityLease {
  attestation?: SandboxSecurityAttestation;
  oast?: SandboxOastLease;
  environmentVariables?: Record<string, string>;
  dispose(): Promise<void>;
}

/**
 * Trusted control-plane boundary for a sandbox. Implementations must apply
 * policy outside the privilege domain of commands executed in the sandbox.
 */
export interface SandboxSecurityController {
  provisionSession(
    request: SandboxSessionSecurityRequest,
  ): Promise<SandboxSessionSecurityLease>;
}

export interface UnifiedSandbox {
  type: SandboxType;
  /** Optional trusted control-plane hook for strict egress and OAST routing. */
  securityController?: SandboxSecurityController;
  execute(
    command: string,
    opts?: SandboxExecuteOptions,
  ): Promise<SandboxExecutionResult>;
}
