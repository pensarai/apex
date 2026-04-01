import type { SpecializedAgentInput } from "../../offSecAgent/types";

export interface ComputerUseAgentInput extends SpecializedAgentInput {
  /** The specific objective to accomplish on the desktop */
  objective: string;

  /** Additional context about the target application or desktop state */
  context?: string;
}
