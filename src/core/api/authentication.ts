import {
  runAuthenticationAgent as _runAuthAgent,
  type AuthenticationAgentInput,
} from "../agents/specialized/authenticationAgent/agent";

// Re-export from the canonical location
export const runAuthenticationAgent = _runAuthAgent;
export type { AuthenticationAgentInput };
