import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";

/**
 * Zod schema for a single question in an `ask_user_questions` tool call.
 *
 * Each question has 2–6 grounded multi-choice options, an optional
 * freeform escape hatch, and an optional `multiSelect` flag. The `id`
 * is a stable identifier used to correlate the answer back to the
 * question when the consumer resumes the agent with a tool-result.
 */
export const AskUserQuestionSchema = z.object({
  id: z
    .string()
    .describe(
      'Stable identifier for the question (e.g. "deployment-model"). Used to correlate the answer.',
    ),
  header: z
    .string()
    .min(1)
    .max(20)
    .describe(
      'Very short tab label (max 20 chars). Examples: "Deployment", "Auth method", "Concerns".',
    ),
  question: z.string(),
  multiSelect: z.boolean().default(false),
  allowFreeform: z.boolean().default(true),
  options: z
    .array(
      z.object({
        id: z.string(),
        label: z.string(),
        description: z.string().optional(),
      }),
    )
    .min(2)
    .max(6),
});

/**
 * Shape of the `ask_user_questions` tool INPUT (one question).
 * Persisted on the assistant message as part of the tool-call input.
 */
export type AskUserQuestion = z.infer<typeof AskUserQuestionSchema>;

/**
 * A single answer submitted by the user for one question.
 *
 * - `questionId` matches `AskUserQuestion.id`.
 * - `selectedOptionIds` is empty if the user only provided freeform text.
 * - `freeformText` is `null` when the user did not use the freeform field.
 */
export interface AskUserQuestionAnswer {
  questionId: string;
  selectedOptionIds: string[];
  freeformText: string | null;
}

/**
 * Shape of the `ask_user_questions` tool RESULT output.
 * Persisted on the tool message when the consumer resumes the agent.
 *
 * `skipped: true` means the user chose to skip rather than answer; the
 * recon adapter (and any other downstream consumer) uses this flag to
 * decide whether to emit a User-Provided Context block.
 */
export interface AskUserQuestionsResult {
  answers: AskUserQuestionAnswer[];
  skipped: boolean;
}

/**
 * Factory for the `ask_user_questions` Apex tool.
 *
 * Takes `ToolContext` for consistency with other tool factories and to
 * leave room for a future transport hook if operator mode needs it.
 *
 * The consuming agent MUST configure `stopWhen(hasToolCall('ask_user_questions'))`
 * — the agent is stopped when the model emits this tool call. The `execute`
 * body below is a sentinel that exists so the tool is well-formed and
 * survives in-process unit testing of the agent; in production the real
 * stopping/transport/resume is handled by the consumer (Console).
 */
export function askUserQuestions(_ctx: ToolContext) {
  return tool({
    description:
      "Stop the agent and ask the user a batch of 2–5 grounded, multi-choice questions. " +
      "Option labels MUST reference something observed in the codebase — not generic templates. " +
      "Each question must include a short `header` field (≤20 chars) used as the tab label in " +
      'the UI (e.g. "Deployment", "Auth method", "Concerns"). ' +
      "The consumer of this agent is responsible for collecting answers and, if applicable, " +
      "resuming with a tool-result in the message history.",
    inputSchema: z.object({
      questions: z.array(AskUserQuestionSchema).min(1).max(5),
    }),
    // The agent is STOPPED by hasToolCall('ask_user_questions') — this body
    // will never run in production. It exists so the tool is well-formed and
    // survives in-process unit testing of the agent with a mocked transport.
    execute: async ({ questions }) => {
      return { ok: true as const, pendingQuestionCount: questions.length };
    },
  });
}
