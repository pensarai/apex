/**
 * Barrel for the guided-onboarding {@link ExplorationAgent}.
 *
 * Re-exports the agent class, its input type, and the shared
 * `ask_user_questions` types so consumers can deserialize tool-call
 * inputs and tool-result outputs without reaching into Apex internals.
 */
export { ExplorationAgent } from "./agent";
export type { ExplorationAgentInput } from "./types";
export type {
  AskUserQuestion,
  AskUserQuestionAnswer,
  AskUserQuestionsResult,
} from "../offSecAgent/tools/askUserQuestions";
