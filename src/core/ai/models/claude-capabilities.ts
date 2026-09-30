type ClaudeCapabilities = { alwaysOnThinking: boolean };

const CLAUDE_CAPABILITIES: Record<string, ClaudeCapabilities> = {
  "claude-sonnet-5": { alwaysOnThinking: false },
  "claude-fable-5": { alwaysOnThinking: true },
};

export function getClaudeCapabilities(
  modelId: string,
): ClaudeCapabilities | undefined {
  return CLAUDE_CAPABILITIES[modelId];
}
