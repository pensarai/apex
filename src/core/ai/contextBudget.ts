/**
 * Tracks token usage across agent steps to enable proactive
 * context management (trim before hitting the hard limit).
 */
export class ContextBudget {
  private contextLimit: number;
  private lastInputTokens = 0;

  constructor(contextLimit: number) {
    this.contextLimit = contextLimit;
  }

  /** Record token usage from the latest step. */
  recordStep(inputTokens: number): void {
    this.lastInputTokens = inputTokens;
  }

  /** Get the last recorded input token count. */
  getLastInputTokens(): number {
    return this.lastInputTokens;
  }

  /** Whether we've crossed the 75% threshold and should proactively trim. */
  shouldTrim(): boolean {
    return this.lastInputTokens > this.contextLimit * 0.75;
  }

  /** Whether we've crossed the 90% threshold and should summarize. */
  shouldSummarize(): boolean {
    return this.lastInputTokens > this.contextLimit * 0.9;
  }

  /** Get the context limit. */
  getContextLimit(): number {
    return this.contextLimit;
  }
}
