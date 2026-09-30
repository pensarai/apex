type ClaudeCapabilities = {
  alwaysOnThinking: boolean;
  bindsThinking?: boolean;
};

const CLAUDE_CAPABILITIES: Record<string, ClaudeCapabilities> = {
  "claude-sonnet-5-5": { alwaysOnThinking: true, bindsThinking: true },
  "claude-opus-5-5": { alwaysOnThinking: true, bindsThinking: true },
  "claude-fable-5-1": { alwaysOnThinking: true, bindsThinking: true },
  "claude-opus-5": { alwaysOnThinking: false },
  "claude-sonnet-5": { alwaysOnThinking: false },
  "claude-fable-5": { alwaysOnThinking: true },
};

export function getClaudeCapabilities(
  modelId: string,
): ClaudeCapabilities | undefined {
  const nativeId = modelId
    .replace(/^(concentrate:|anthropic\/)/, "")
    .replace(/(\d)\.(\d)/g, "$1-$2");
  return CLAUDE_CAPABILITIES[nativeId];
}
