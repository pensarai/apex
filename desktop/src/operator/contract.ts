import type { LoadedTopology } from "../../../src/core/agents/offSecAgent/tools/topologyRecords";
import type { BackgroundJobState } from "../../../src/core/eventBus";
import type { Goal } from "../../../src/core/goals/types";
import type { DisplayReasoning } from "../../../src/core/session/persistence";
import type { WorkflowData } from "../../../src/core/workflows/pentest-progress";

import type { OperatorFrame } from "./live";

export type OperatorMode = "manual" | "auto" | "plan";

export interface OperatorAttachment {
  name: string;
  base64: string;
}

export interface OperatorLaunch {
  attachments?: OperatorAttachment[];
  skill?: string;
  skillArguments?: string[];
  goal?: { objective: string; maxRounds?: number };
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
  reasoning?: DisplayReasoning;
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

export type OperatorActivity =
  | "waiting"
  | "thinking"
  | "responding"
  | "working";

export interface OperatorSnapshot {
  goal?: Goal | null;
  goalsEnabled?: boolean;
  goalPaused?: boolean;
  processes?: BackgroundJobState[];
  revision: number;
  activity?: OperatorActivity;
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
    parentToolCallId?: string;
    modelLoading?: string;
    spawnedAt?: string;
    completedAt?: string;
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
  | { type: "goal"; command: string; attachments?: OperatorAttachment[] }
  | { type: "resume-goal" }
  | { type: "send"; text: string; attachments?: OperatorAttachment[] }
  | {
      type: "skill";
      slug: string;
      autopilot?: boolean;
      arguments?: string[];
      attachments?: OperatorAttachment[];
    }
  | { type: "mode"; mode: OperatorMode }
  | { type: "model"; id: string }
  | { type: "approval"; id: string; decision: "approve" | "deny" | "auto" }
  | { type: "cancel" }
  | { type: "cancel-command"; toolCallId: string }
  | { type: "cancel-process"; jobId: string }
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
export type OperatorSessionRequests = {
  operatorSkills: Call<void, OperatorSnapshot["skills"]>;
  operatorGoal: Call<
    {
      command: string;
      mode?: OperatorMode;
      attachments?: OperatorAttachment[];
    },
    OperatorSnapshot
  >;
  operatorAttackSurface: Call<{ sessionId: string }, LoadedTopology>;
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
export interface OperatorTab {
  tabId: string;
  cwd: string;
  snapshot: OperatorSnapshot;
}
export type OperatorRequests = {
  [K in keyof OperatorSessionRequests]: Call<
    { tabId: string } & (OperatorSessionRequests[K]["params"] extends void
      ? object
      : OperatorSessionRequests[K]["params"]),
    OperatorSessionRequests[K]["response"]
  >;
} & {
  operatorOpen: Call<{ sessionId?: string; reuseEmpty?: boolean }, OperatorTab>;
  operatorTabs: Call<void, OperatorTab[]>;
  operatorClose: Call<{ tabId: string; stop?: boolean }, void>;
  operatorSetDirectory: Call<{ tabId: string; cwd: string }, string>;
};
export type OperatorMessages = {
  operatorSnapshot: { tabId: string; frame: OperatorFrame };
};
