export type ClaudeThinkingEffort = "low" | "medium" | "high" | "xhigh" | "max";

export type ClaudeCapabilities = {
  alwaysOnThinking: boolean;
  bindsThinking?: boolean;
  defaultEffort: ClaudeThinkingEffort;
};

const CLAUDE_CAPABILITIES: Record<string, ClaudeCapabilities> = {
  "claude-haiku-5-5": {
    alwaysOnThinking: false,
    bindsThinking: true,
    defaultEffort: "medium",
  },
  "claude-sonnet-5-5": {
    alwaysOnThinking: true,
    bindsThinking: true,
    defaultEffort: "high",
  },
  "claude-opus-5-5": {
    alwaysOnThinking: true,
    bindsThinking: true,
    defaultEffort: "medium",
  },
  "claude-fable-5-1": {
    alwaysOnThinking: true,
    bindsThinking: true,
    defaultEffort: "high",
  },
  "claude-opus-5": { alwaysOnThinking: false, defaultEffort: "high" },
  "claude-sonnet-5": { alwaysOnThinking: false, defaultEffort: "high" },
  "claude-fable-5": { alwaysOnThinking: true, defaultEffort: "high" },
};

export function getClaudeCapabilities(
  modelId: string,
): ClaudeCapabilities | undefined {
  const nativeId = modelId
    .replace(/^(concentrate:|pensar:)/, "")
    .replace(/^(?:(?:us|global|eu|au|jp)\.)?anthropic[./]/, "")
    .replace(/(\d)\.(\d)/g, "$1-$2");
  return CLAUDE_CAPABILITIES[nativeId];
}
