import type { AgenticTranscript } from "../types";

export interface CreateSessionInput {
  /** The adversarial attack message (sent last). */
  prompt: string;
  /** Trusted-context turns sent before the attack (e.g. a planted secret). */
  seedMessages?: string[];
  /** Used to label the session in mock/dry-run transcripts. */
  caseId?: string;
}

/**
 * Target adapter — the only target-specific seam. Everything else (corpus,
 * canary oracle, runner, findings) is target-agnostic. Mirrors the harness
 * client shape: create a session (seed turns then attack), poll to terminal,
 * read the transcript.
 */
export interface TargetAdapter {
  createSession(input: CreateSessionInput): Promise<{ sessionId: string }>;
  pollUntilTerminal(sessionId: string): Promise<AgenticTranscript>;
  getTranscript(sessionId: string): Promise<AgenticTranscript>;
  /** Optional cleanup of per-run resources (e.g. throwaway corpora). */
  dispose?(): Promise<void>;
}
