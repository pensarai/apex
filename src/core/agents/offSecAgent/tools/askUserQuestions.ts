import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";

export const ASK_USER_QUESTIONS_TOOL_NAME = "ask_user_questions" as const;

/**
 * Zod schema for a single question in an `ask_user_questions` tool call.
 *
 * Schema is deliberately permissive (no `min`/`max` on strings or arrays,
 * no `default()` on booleans). Anthropic / Bedrock has no native JSON
 * mode, so AI SDK structured-output / repair falls back to text-based
 * JSON parsing — and complex schemas with constraints make the repair
 * model unable to emit parseable JSON, which kills the whole stream
 * with "No object generated: could not parse the response".
 *
 * Constraints (1–5 questions, 2–3 options each, ≤20-char header, etc.)
 * live in the tool's `description` as prose guidance to the model.
 * The UI layer normalizes missing optional fields (`multiSelect ?? false`,
 * `allowFreeform ?? true`) and clamps option lists defensively.
 */
export const AskUserQuestionSchema = z.object({
  id: z
    .string()
    .describe(
      'Stable identifier for the question (e.g. "deployment-model"). Used to correlate the answer.',
    ),
  header: z
    .string()
    .describe(
      'Very short tab label, ideally ≤20 chars. Examples: "Deployment", "Auth method", "Concerns".',
    ),
  question: z.string(),
  multiSelect: z
    .boolean()
    .optional()
    .describe("True if the user can pick multiple options. Defaults to false."),
  allowFreeform: z
    .boolean()
    .optional()
    .describe(
      "True if the user can supply a freeform answer in addition to the predefined options. Defaults to true.",
    ),
  options: z
    .array(
      z.object({
        id: z.string(),
        label: z.string(),
        description: z.string().optional(),
      }),
    )
    .describe(
      "2–3 predefined options for the user to choose from. Do NOT include " +
        '"Other" or "Type something" here — the UI renders a freeform input ' +
        "automatically when `allowFreeform` is true. Keep options short and " +
        "grounded in observed code.",
    ),
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
      "Stop the agent and ask the user a batch of grounded multi-choice questions. " +
      "Aim for 1–5 questions per call. Each question MUST include: a short `header` " +
      '(ideally ≤20 chars, used as the tab label, e.g. "Deployment", "Auth method", "Concerns"); ' +
      "the `question` text; and 2–3 predefined `options`. Option labels MUST reference something " +
      "observed in the codebase — not generic templates. " +
      "Do NOT include an extra 'Other' or 'Type something' option in the predefined list — the UI " +
      "renders a freeform input automatically when `allowFreeform` is true (the default). Keep " +
      "predefined options short (a few words each) so the user can scan them quickly. " +
      "The consumer of this agent collects answers and resumes with a tool-result in the message history.",
    inputSchema: z.object({
      questions: z.array(AskUserQuestionSchema),
    }),
    // The agent is STOPPED by hasToolCall('ask_user_questions') — this body
    // will never run in production. It exists so the tool is well-formed and
    // survives in-process unit testing of the agent with a mocked transport.
    execute: async ({ questions }) => {
      return { ok: true as const, pendingQuestionCount: questions.length };
    },
  });
}
