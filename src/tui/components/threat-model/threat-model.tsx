import { useState, useEffect, useCallback, useRef } from "react";
import { useKeyboard } from "@opentui/react";
import { exec } from "child_process";
import { existsSync } from "fs";
import { join } from "path";

import { sessions, type SessionInfo } from "../../../core/session";
import { runThreatModelAgent, type ThreatModelResult } from "../../../core/api";
import { useAgent } from "../../context/agent";
import { useRoute } from "../../context/route";
import { useConfig } from "../../context/config";
import { useTheme } from "../../theme";
import { SpinnerDots } from "../sprites";

// ---------------------------------------------------------------------------
// Phase definitions
// ---------------------------------------------------------------------------

const PHASE_NAMES: Record<string, string> = {
  "application-context": "Application Context Discovery",
  "attack-surface": "Attack Surface Discovery",
  "deployment-context": "Deployment Context Analysis",
  "security-controls": "Security Controls Analysis",
  "architecture-synthesis": "Architecture Synthesis",
  "attack-path-synthesis": "Attack Path Synthesis",
};

const PHASE_ORDER = [
  "application-context",
  "attack-surface",
  "deployment-context",
  "security-controls",
  "architecture-synthesis",
  "attack-path-synthesis",
] as const;

type PhaseId = (typeof PHASE_ORDER)[number];
type PhaseStatus = "pending" | "active" | "completed" | "failed";

type OverallPhase = "loading" | "running" | "completed" | "error";

// ---------------------------------------------------------------------------
// ThreatModel component
// ---------------------------------------------------------------------------

export default function ThreatModel({ sessionId }: { sessionId: string }) {
  const { colors } = useTheme();
  const route = useRoute();
  const config = useConfig();
  const { model, setThinking, setIsExecuting } = useAgent();

  // Session state
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [overallPhase, setOverallPhase] = useState<OverallPhase>("loading");

  // Phase tracking
  const [phaseStatuses, setPhaseStatuses] = useState<
    Record<PhaseId, PhaseStatus>
  >(() => {
    const initial: Record<string, PhaseStatus> = {};
    for (const id of PHASE_ORDER) {
      initial[id] = "pending";
    }
    return initial as Record<PhaseId, PhaseStatus>;
  });

  // Result
  const [result, setResult] = useState<ThreatModelResult | null>(null);

  // Abort
  const abortControllerRef = useRef<AbortController | null>(null);

  // -------------------------------------------------------------------------
  // Load session
  // -------------------------------------------------------------------------

  useEffect(() => {
    async function load() {
      try {
        const s = await sessions.get(sessionId);
        if (!s) {
          setError(`Session not found: ${sessionId}`);
          setOverallPhase("error");
          return;
        }
        setSession(s);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to load session");
        setOverallPhase("error");
      }
    }
    load();
  }, [sessionId]);

  // -------------------------------------------------------------------------
  // Cleanup
  // -------------------------------------------------------------------------

  useEffect(() => {
    return () => {
      abortControllerRef.current?.abort();
    };
  }, []);

  // -------------------------------------------------------------------------
  // Run threat model
  // -------------------------------------------------------------------------

  const startThreatModel = useCallback(
    async (s: SessionInfo) => {
      setOverallPhase("running");
      setIsExecuting(true);
      setThinking(true);

      const controller = new AbortController();
      abortControllerRef.current = controller;

      const cwd = s.config?.cwd || s.targets[0] || process.cwd();

      const run = runThreatModelAgent({
        cwd,
        session: s,
        model: model.id,
        abortSignal: controller.signal,
        authConfig: {
          anthropicAPIKey: config.data.anthropicAPIKey ?? undefined,
          openAiAPIKey: config.data.openAiAPIKey ?? undefined,
          openRouterAPIKey: config.data.openRouterAPIKey ?? undefined,
          local: config.data.localModelUrl
            ? { baseURL: config.data.localModelUrl }
            : undefined,
        },
      });

      try {
        for await (const event of run) {
          switch (event.type) {
            case "subagent-spawn": {
              const phaseId = event.subagentId as PhaseId;
              if (phaseId in PHASE_NAMES) {
                setPhaseStatuses((prev) => ({
                  ...prev,
                  [phaseId]: "active",
                }));
              }
              break;
            }
            case "subagent-complete": {
              const phaseId = event.subagentId as PhaseId;
              if (phaseId in PHASE_NAMES) {
                setPhaseStatuses((prev) => ({
                  ...prev,
                  [phaseId]:
                    event.status === "completed" ? "completed" : "failed",
                }));
              }
              break;
            }
            case "error":
              console.error("Threat model error:", event.error);
              break;
          }
        }

        const threatModelResult = await run.result;
        setResult(threatModelResult);
        setOverallPhase("completed");
      } catch (e) {
        if (e instanceof Error && e.name === "AbortError") {
          // User aborted
        } else {
          setError(e instanceof Error ? e.message : "Unknown error");
          setOverallPhase("error");
        }
      } finally {
        setThinking(false);
        setIsExecuting(false);
      }
    },
    [model.id, config.data, setThinking, setIsExecuting],
  );

  // -------------------------------------------------------------------------
  // Auto-start when session loads
  // -------------------------------------------------------------------------

  useEffect(() => {
    if (session && overallPhase === "loading") {
      startThreatModel(session);
    }
  }, [session, overallPhase, startThreatModel]);

  // -------------------------------------------------------------------------
  // Keyboard
  // -------------------------------------------------------------------------

  useKeyboard((key) => {
    if (key.name === "escape") {
      abortControllerRef.current?.abort();
      route.navigate({ type: "base", path: "home" });
      return;
    }

    if (key.name === "return" && overallPhase === "completed") {
      openReport();
      return;
    }
  });

  // -------------------------------------------------------------------------
  // Open report
  // -------------------------------------------------------------------------

  const openReport = useCallback(() => {
    if (!session) return;
    const mdPath = join(session.rootPath, "threat-model", "threat-model.md");
    if (existsSync(mdPath)) {
      exec(`open "${mdPath}"`);
    } else {
      exec(`open "${session.rootPath}"`);
    }
  }, [session]);

  // -------------------------------------------------------------------------
  // Render: Loading
  // -------------------------------------------------------------------------

  if (overallPhase === "loading" && !session) {
    return (
      <box
        flexDirection="column"
        width="100%"
        height="100%"
        alignItems="center"
        justifyContent="center"
        backgroundColor={colors.background}
      >
        <SpinnerDots label="Loading session..." />
      </box>
    );
  }

  // -------------------------------------------------------------------------
  // Render: Error
  // -------------------------------------------------------------------------

  if (overallPhase === "error") {
    return (
      <box
        flexDirection="column"
        width="100%"
        height="100%"
        alignItems="center"
        justifyContent="center"
        backgroundColor={colors.background}
        gap={1}
      >
        <text fg={colors.error} content="Threat Model Failed" />
        {error && <text fg={colors.textMuted} content={error} />}
        <text fg={colors.textMuted} content="Press ESC to go back" />
      </box>
    );
  }

  // -------------------------------------------------------------------------
  // Render: Running / Completed
  // -------------------------------------------------------------------------

  return (
    <box
      flexDirection="column"
      width="100%"
      height="100%"
      backgroundColor={colors.background}
      paddingLeft={2}
      paddingRight={2}
      paddingTop={1}
      gap={1}
    >
      {/* Title */}
      <box flexDirection="row" gap={1}>
        <text fg={colors.primary} content="Threat Model" />
        {session && (
          <text
            fg={colors.textMuted}
            content={`- ${session.config?.cwd || session.targets[0] || "unknown"}`}
          />
        )}
      </box>

      {/* Phase list */}
      <box flexDirection="column" gap={0}>
        {PHASE_ORDER.map((phaseId) => (
          <PhaseRow
            key={phaseId}
            phaseId={phaseId}
            status={phaseStatuses[phaseId]}
          />
        ))}
      </box>

      {/* Completion banner */}
      {overallPhase === "completed" && result && (
        <CompletionBanner result={result} />
      )}

      {/* Footer hint */}
      <box flexDirection="row" gap={1} marginTop={1}>
        {overallPhase === "completed" ? (
          <text
            fg={colors.textMuted}
            content="Press ENTER to open report | ESC to go back"
          />
        ) : (
          <text fg={colors.textMuted} content="Press ESC to abort" />
        )}
      </box>
    </box>
  );
}

// ---------------------------------------------------------------------------
// PhaseRow — single phase with status indicator
// ---------------------------------------------------------------------------

function PhaseRow({
  phaseId,
  status,
}: {
  phaseId: PhaseId;
  status: PhaseStatus;
}) {
  const { colors } = useTheme();
  const label = PHASE_NAMES[phaseId] || phaseId;

  if (status === "completed") {
    return (
      <box flexDirection="row" gap={1}>
        <text fg={colors.success} content="  [done]" />
        <text fg={colors.text} content={label} />
      </box>
    );
  }

  if (status === "active") {
    return (
      <box flexDirection="row" gap={1}>
        <SpinnerDots label={label} />
      </box>
    );
  }

  if (status === "failed") {
    return (
      <box flexDirection="row" gap={1}>
        <text fg={colors.error} content="  [fail]" />
        <text fg={colors.error} content={label} />
      </box>
    );
  }

  // pending
  return (
    <box flexDirection="row" gap={1}>
      <text fg={colors.textMuted} content="  [ -- ]" />
      <text fg={colors.textMuted} content={label} />
    </box>
  );
}

// ---------------------------------------------------------------------------
// CompletionBanner
// ---------------------------------------------------------------------------

function CompletionBanner({ result }: { result: ThreatModelResult }) {
  const { colors } = useTheme();
  const { summary } = result;
  const { bySeverity, totalAttackPaths } = summary;

  const parts: string[] = [];
  if (bySeverity.critical > 0) parts.push(`${bySeverity.critical} critical`);
  if (bySeverity.high > 0) parts.push(`${bySeverity.high} high`);
  if (bySeverity.medium > 0) parts.push(`${bySeverity.medium} medium`);
  if (bySeverity.low > 0) parts.push(`${bySeverity.low} low`);

  const breakdown = parts.length > 0 ? parts.join(", ") : "none";
  const bannerText = `Threat Model Complete -- ${totalAttackPaths} attack paths: ${breakdown}`;

  return (
    <box
      flexDirection="column"
      borderStyle="rounded"
      borderColor={colors.success}
      paddingLeft={1}
      paddingRight={1}
    >
      <text fg={colors.success} content={bannerText} />
    </box>
  );
}
