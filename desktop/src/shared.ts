import type { RPCSchema } from "electrobun/view";

import type { OperatorMessages, OperatorRequests } from "./operator/contract";
import type { PentestRequests } from "./pentest/contract";
import type { SettingsRequests } from "./settings/contract";

export interface SessionRow {
  id: string;
  name: string;
  targets: string[];
  updated: number;
  created: number;
}

export interface FindingRow {
  title: string;
  severity: string;
  endpoint: string;
  description: string;
  impact: string;
  evidence: string;
  remediation: string;
}
export interface SkillRow {
  slug: string;
  name: string;
  source: string;
  description: string;
  scripts: string[];
}
export type RunLocation = { store?: string; id?: string };
export interface RunRow {
  id: string;
  target: string;
  prompt: string;
  model: string;
  status: string;
  updated: string;
}

export interface RunDetail {
  connection: string;
  error?: string;
  status?: string;
  attempt?: string;
  control?: { revision: number; intent: string };
  approvals: { id: string; tool: string; input: string }[];
  transcript: { id: string; role: string; text: string }[];
}

export type RunAction =
  | { type: "pause" | "stop"; revision: number }
  | { type: "resume"; attempt: string }
  | { type: "approved" | "denied"; approvalId: string };

type Call<P, R> = { params: P; response: R };
export type DesktopRPC = {
  bun: RPCSchema<{
    requests: OperatorRequests &
      SettingsRequests &
      PentestRequests & {
        windowAction: Call<
          { action: "close" | "minimize" | "toggle-maximize" },
          void
        >;
        workspace: Call<
          void,
          {
            cwd: string;
            version: string;
            accepted: boolean;
            hasProvider: boolean;
          }
        >;
        toolSelection: Call<
          { id: string },
          { name: string; enabled: boolean }[]
        >;
        setToolEnabled: Call<
          { id: string; name: string; enabled: boolean },
          void
        >;
        chooseFolder: Call<void, string>;
        accept: Call<void, void>;
        sessions: Call<void, SessionRow[]>;
        artifacts: Call<
          { id: string },
          { report: string | null; findings: FindingRow[] }
        >;
        deleteSession: Call<{ id: string }, void>;
        openSessionDirectory: Call<{ id: string }, void>;
        skills: Call<void, SkillRow[]>;
        skillContent: Call<{ slug: string }, string>;
        openRunsCommand: Call<{ command: string }, RunLocation>;
        quit: Call<void, void>;
        runs: Call<{ store?: string }, RunRow[]>;
        watchRun: Call<{ store?: string; id: string; key: string }, void>;
        unwatchRun: Call<{ key: string }, void>;
        act: Call<{ store?: string; id: string; action: RunAction }, void>;
        startRun: Call<{ store?: string; spec: string }, string>;
        startTerminal: Call<{ id?: string; cols: number; rows: number }, void>;
      };
    messages: {
      input: { data: string };
      resize: { cols: number; rows: number };
    };
  }>;
  webview: RPCSchema<{
    requests: Record<never, never>;
    messages: OperatorMessages & {
      sessionCommand: { type: "new" | "close" };
      runView: { key: string; view?: RunDetail; error?: string };
      output: { bytes: string };
      exited: { code: number };
    };
  }>;
};
