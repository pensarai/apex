import {
  SiemTriageAgent,
  type SiemTriageAgentInput,
  type SiemTriageResult,
} from "../agents/specialized/siemTriage/agent";

export function runSiemTriageAgent(
  input: SiemTriageAgentInput,
): Promise<SiemTriageResult> {
  const agent = new SiemTriageAgent(input);

  if (!input.eventBus) {
    agent.eventBus.on("text-delta", (event) =>
      process.stdout.write(event.text),
    );
    agent.eventBus.on("tool-call-complete", (event) =>
      console.log(`→ ${event.toolName}`),
    );
    agent.eventBus.on("error", (event) =>
      console.error("SIEM triage agent error:", event.error),
    );
  }

  return agent.consume();
}

export type {
  SiemAlertEvidence,
  SiemCodeChange,
  SiemLogEvent,
  SiemLogSearch,
  SiemLogSearchQuery,
  SiemLogSearchResult,
  SiemRepositoryInvestigation,
  SiemTriageAgentInput,
  SiemTriageResult,
} from "../agents/specialized/siemTriage/agent";
export {
  SiemCodeChangeSchema,
  SiemTriageResultSchema,
  SiemTriageSeveritySchema,
  SiemTriageVerdictSchema,
} from "../agents/specialized/siemTriage/agent";
