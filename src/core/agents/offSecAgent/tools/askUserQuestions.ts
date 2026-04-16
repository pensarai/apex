import { tool } from "ai";
import { z } from "zod";
import type { ToolContext } from "./types";

export const ASK_USER_QUESTIONS_TOOL_NAME = "ask_user_questions" as const;

// Schema is deliberately permissive — constrained schemas cause the AI SDK
// repair model to emit unparseable JSON. Constraints live in the tool
// description; the UI normalizes defensively.
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

export type AskUserQuestion = z.infer<typeof AskUserQuestionSchema>;

export interface AskUserQuestionAnswer {
  questionId: string;
  selectedOptionIds: string[];
  freeformText: string | null;
}

export interface AskUserQuestionsResult {
  answers: AskUserQuestionAnswer[];
  skipped: boolean;
}

// Agent is paused via hasToolCall before execute runs; body is a fallback.
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
    execute: async ({ questions }) => {
      return { ok: true as const, pendingQuestionCount: questions.length };
    },
  });
}
