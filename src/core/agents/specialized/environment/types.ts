import { z } from "zod";
import type { SpecializedAgentInput } from "../../offSecAgent/types";
import type { UnifiedSandbox } from "../../offSecAgent/tools/sandbox";

/**
 * Structured result returned by the environment agent via the `response` tool.
 */
export const EnvironmentResultSchema = z.object({
  url: z
    .string()
    .describe("The URL where the application is accessible"),
  status: z
    .enum(["ready", "failed"])
    .describe("The status of the development environment"),
  stepsTaken: z
    .string()
    .describe("The steps taken to start the development environment"),
  authenticationDetails: z
    .string()
    .describe(
      "Details on how to register a user and authenticate within the development environment",
    ),
});

export type EnvironmentResult = z.infer<typeof EnvironmentResultSchema>;

export interface EnvironmentVariable {
  name: string;
  value: string;
}

/**
 * Configuration for the dev environment setup.
 */
export interface DevEnvironmentConfig {
  startCommand?: string | null;
  installCommand?: string | null;
  devEnvironmentInstructions?: string | null;
  environmentVariables?: EnvironmentVariable[];
}

/**
 * Input for the EnvironmentAgent constructor.
 */
export interface EnvironmentAgentInput extends SpecializedAgentInput {
  /** Root path of the cloned repository */
  cwd: string;

  /** Optional dev environment configuration hints */
  config?: DevEnvironmentConfig;

  /**
   * Optional pre-configured sandbox for isolated code execution.
   *
   * When provided, tools like `execute_command`, `create_file`, and
   * `update_file` automatically route operations through the sandbox
   * instead of the local filesystem.
   */
  sandbox?: UnifiedSandbox;
}
