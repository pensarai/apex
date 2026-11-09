import type { WorkflowData } from "../../../src/core/workflows/pentest-progress";

import type { OperatorFrame } from "./live";

export type OperatorMode = "manual" | "auto" | "plan";

export interface OperatorLaunch {
  skill?: "threat-model" | "prompt-injection";
  skillOutput?: string;
  target?: string;
  prompt?: string;
  displayPrompt?: string;
  name?: string;
  mode?: OperatorMode;
  sandbox?: boolean;
  strikeMode?: boolean;
  lanceMode?: boolean;
  taskDriven?: boolean;
  model?: string;
  headers?: Record<string, string>;
  headerLines?: string;
  scopeConstraints?: {
    allowedHosts?: string[];
    allowedPorts?: number[];
    strictScope?: boolean;
  };
  authCredentials?: {
    username?: string;
    password?: string;
    loginUrl?: string;
    apiKey?: string;
    role?: string;
    context?: string;
  }[];
  authenticationInstructions?: string;
  enumerateSubdomains?: boolean;
  codebasePath?: string;
  guidance?: string;
  promptInjectionLibrarySource?: string;
}

export interface Question {
  id: string;
  header: string;
  question: string;
  multiSelect?: boolean;
  allowFreeform?: boolean;
  options: { id: string; label: string; description?: string }[];
}

export interface OperatorMessage {
  role: "user" | "system" | "assistant" | "tool";
  content: string;
  createdAt: string;
  toolCallId?: string;
  toolName?: string;
  args?: unknown;
  result?: unknown;
  status?: string;
  logs?: string[];
  workflowData?: WorkflowData;
}

export interface OperatorSnapshot {
  revision: number;
  sessionId?: string;
  name?: string;
  target?: string;
  status: "idle" | "running" | "stopping" | "waiting";
  mode: OperatorMode;
  model?: string;
  modelLoading?: string;
  strike: boolean;
  lance: boolean;
  error?: string;
  messages: OperatorMessage[];
  subagents: {
    id: string;
    name: string;
    status: string;
    messages: OperatorMessage[];
    input: unknown;
  }[];
  approvals: {
    id: string;
    toolName: string;
    args: Record<string, unknown>;
    reasoning?: string;
  }[];
  questions?: { toolCallId: string; questions: Question[] };
  queue: { id: string; text: string }[];
  skills: { slug: string; name: string; description: string }[];
  headers: { name: string; displayValue: string }[];
  plan: string | null;
  reviewPlan: boolean;
  usage: { input: number; output: number; context?: number; limit?: number };
}

export type OperatorAction =
  | { type: "send"; text: string }
  | { type: "skill"; slug: string; autopilot?: boolean; arguments?: string[] }
  | { type: "mode"; mode: OperatorMode }
  | { type: "approval"; id: string; decision: "approve" | "deny" | "auto" }
  | { type: "cancel" | "cancel-command" }
  | { type: "queue"; id: string; operation: "remove" | "send-now" }
  | {
      type: "answer";
      toolCallId: string;
      answers: {
        questionId: string;
        selectedOptionIds: string[];
        freeformText: string | null;
      }[];
      skip: boolean;
    }
  | { type: "plan"; approve: boolean }
  | { type: "headers"; command: string }
  | { type: "open-folder" };
type Call<P, R> = { params: P; response: R };
export type OperatorRequests = {
  operatorArguments: Call<{ command: string }, OperatorLaunch>;
  operatorWatch: Call<{ key: string }, OperatorSnapshot>;
  operatorUnwatch: Call<{ key: string }, void>;
  operatorState: Call<void, OperatorSnapshot>;
  operatorStart: Call<OperatorLaunch, OperatorSnapshot>;
  operatorResume: Call<{ id: string }, OperatorSnapshot>;
  operatorAction: Call<
    { sessionId: string; action: OperatorAction },
    OperatorSnapshot
  >;
  operatorScreenshot: Call<
    { sessionId: string; toolCallId: string; agentId?: string },
    string
  >;
};
export type OperatorMessages = { operatorSnapshot: OperatorFrame };
