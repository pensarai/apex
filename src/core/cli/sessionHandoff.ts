export interface SessionHandoffSummaryInput {
  sessionId: string;
  sessionPath: string;
  findingsPath: string;
  pocsPath: string;
  reportPath?: string | null;
}

export function formatSessionHandoffSummary(
  input: SessionHandoffSummaryInput,
): string {
  return [
    `Session:       ${input.sessionId}`,
    `Session path:  ${input.sessionPath}`,
    `Findings path: ${input.findingsPath}`,
    `POCs:          ${input.pocsPath}`,
    ...(input.reportPath ? [`Report:        ${input.reportPath}`] : []),
  ].join("\n");
}
