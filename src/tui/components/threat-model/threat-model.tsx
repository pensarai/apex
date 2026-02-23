import { useState, useEffect, useCallback, useRef } from "react";
import { useKeyboard } from "@opentui/react";
import { exec } from "child_process";

import { sessions, type SessionInfo } from "../../../core/session";
import { runStrideThreatModel } from "../../../core/api/threatModel";
import type { ThreatModelWorkflowResult } from "../../../core/workflows/threatModel";
import { useAgent } from "../../context/agent";
import { useRoute } from "../../context/route";
import { useDialog } from "../../context/dialog";
import { useTheme } from "../../theme";
import AgentDisplay, { type DisplayMessage } from "../agent-display";
import { SpinnerDots } from "../sprites";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Phase =
  | "loading"
  | "attack-surface"
  | "deployment"
  | "controls"
  | "synthesis"
  | "completed"
  | "error";

const phaseLabels: Record<Phase, string> = {
  loading: "Loading",
  "attack-surface": "Discovering Attack Surface",
  deployment: "Analyzing Deployment Context",
  controls: "Extracting Security Controls",
  synthesis: "Synthesizing Threat Model",
  completed: "Completed",
  error: "Error",
};

// ---------------------------------------------------------------------------
// ThreatModel — main component
// ---------------------------------------------------------------------------

export default function ThreatModel({ sessionId }: { sessionId: string }) {
  const { colors } = useTheme();
  const route = useRoute();
  const { model, setThinking, setIsExecuting } = useAgent();
  const { stack, externalDialogOpen } = useDialog();

  // Session
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>("loading");

  // Result
  const [result, setResult] = useState<ThreatModelWorkflowResult | null>(null);

  // Abort
  const [abortController, setAbortController] =
    useState<AbortController | null>(null);

  // Messages
  const [messages, setMessages] = useState<DisplayMessage[]>([]);
  const textRef = useRef("");
  const sourceRef = useRef<string | null>(null);

  // Timing
  const [startTime, setStartTime] = useState<Date | null>(null);

  // -------------------------------------------------------------------------
  // Load session
  // -------------------------------------------------------------------------

  useEffect(() => {
    async function load() {
      try {
        const s = await sessions.get(sessionId);
        if (!s) {
          setError(`Session not found: ${sessionId}`);
          setPhase("error");
          return;
        }
        setSession(s);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to load session");
        setPhase("error");
      }
    }
    load();
  }, [sessionId]);

  // Cleanup
  useEffect(() => {
    return () => {
      abortController?.abort();
    };
  }, [abortController]);

  // -------------------------------------------------------------------------
  // Helpers: message management
  // -------------------------------------------------------------------------

  const appendText = useCallback((source: string, text: string) => {
    if (sourceRef.current !== source) {
      textRef.current = "";
      sourceRef.current = source;
    }
    textRef.current += text;
    const accumulated = textRef.current;
    setMessages((prev) => {
      const last = prev[prev.length - 1];
      if (
        last &&
        last.role === "assistant" &&
        (last as DisplayMessage & { _source?: string })._source === source
      ) {
        const updated = [...prev];
        updated[updated.length - 1] = { ...last, content: accumulated };
        return updated;
      }
      return [
        ...prev,
        {
          role: "assistant",
          content: accumulated,
          createdAt: new Date(),
          _source: source,
        } as DisplayMessage & { _source: string },
      ];
    });
  }, []);

  const addToolCall = useCallback(
    (toolCallId: string, toolName: string, args?: Record<string, unknown>) => {
      textRef.current = "";
      sourceRef.current = null;

      const description =
        typeof args?.toolCallDescription === "string"
          ? args.toolCallDescription
          : toolName;

      const msg: DisplayMessage = {
        role: "tool",
        content: description,
        toolCallId,
        toolName,
        args,
        status: "pending",
        createdAt: new Date(),
      };

      setMessages((prev) => {
        if (prev.some((m) => m.toolCallId === toolCallId)) return prev;
        return [...prev, msg];
      });
    },
    [],
  );

  const updateToolResult = useCallback(
    (toolCallId: string, toolName: string, resultData?: unknown) => {
      textRef.current = "";
      sourceRef.current = null;
      setMessages((prev) => {
        const idx = prev.findIndex((m) => m.toolCallId === toolCallId);
        if (idx !== -1) {
          const updated = [...prev];
          updated[idx] = {
            ...updated[idx]!,
            status: "completed" as const,
            result: resultData,
          };
          return updated;
        }
        return [
          ...prev,
          {
            role: "tool" as const,
            content: toolName,
            toolCallId,
            toolName,
            status: "completed" as const,
            result: resultData,
            createdAt: new Date(),
          },
        ];
      });
    },
    [],
  );

  // -------------------------------------------------------------------------
  // Start the threat model workflow
  // -------------------------------------------------------------------------

  const startThreatModel = useCallback(
    async (s: SessionInfo) => {
      const cwd = s.config?.cwd;
      if (!cwd) {
        setError("No codebase path (--cwd) configured for this session");
        setPhase("error");
        return;
      }

      setPhase("attack-surface");
      setStartTime(new Date());
      setIsExecuting(true);
      setThinking(true);

      const controller = new AbortController();
      setAbortController(controller);

      try {
        const threatModelResult = await runStrideThreatModel({
          cwd,
          session: s,
          model: model.id,
          abortSignal: controller.signal,
          callbacks: {
            onTextDelta: (d) => {
              setThinking(false);
              appendText("agent", d.text);
            },
            onToolCall: (d) => {
              setThinking(false);
              addToolCall(
                d.toolCallId,
                d.toolName,
                d.input as Record<string, unknown> | undefined,
              );
            },
            onToolResult: (d) => {
              setThinking(true);
              updateToolResult(d.toolCallId, d.toolName, d.output);
            },
            subagentCallbacks: {
              onTextDelta: (d) => {
                setThinking(false);
                appendText(d.subagentId ?? "subagent", d.text);
              },
              onToolCall: (d) => {
                setThinking(false);
                addToolCall(
                  d.toolCallId,
                  d.toolName,
                  d.input as Record<string, unknown> | undefined,
                );
              },
              onToolResult: (d) => {
                setThinking(true);
                updateToolResult(d.toolCallId, d.toolName, d.output);
              },
              onError: (e) => {
                console.error("Subagent error:", e);
              },
            },
          },
        });

        setResult(threatModelResult);
        setPhase("completed");
      } catch (e) {
        if (e instanceof Error && e.name === "AbortError") {
          // User aborted
        } else {
          setError(e instanceof Error ? e.message : "Unknown error");
          setPhase("error");
        }
      } finally {
        setThinking(false);
        setIsExecuting(false);
      }
    },
    [
      model.id,
      setThinking,
      setIsExecuting,
      appendText,
      addToolCall,
      updateToolResult,
    ],
  );

  // Auto-start when session loads
  useEffect(() => {
    if (session && phase === "loading") {
      startThreatModel(session);
    }
  }, [session, phase, startThreatModel]);

  // -------------------------------------------------------------------------
  // Keyboard
  // -------------------------------------------------------------------------

  useKeyboard((key) => {
    if (stack.length > 0 || externalDialogOpen) return;

    if (key.name === "escape") {
      abortController?.abort();
      route.navigate({ type: "base", path: "home" });
      return;
    }

    if (key.name === "return" && phase === "completed" && result) {
      exec(`open "${result.markdownPath}"`);
      return;
    }
  });

  // -------------------------------------------------------------------------
  // Render: Loading
  // -------------------------------------------------------------------------

  if (phase === "loading" && !session) {
    return (
      <box
        flexDirection="column"
        width="100%"
        height="100%"
        alignItems="center"
        justifyContent="center"
        flexGrow={1}
      >
        <SpinnerDots label="Loading session..." fg={colors.primary} />
      </box>
    );
  }

  // -------------------------------------------------------------------------
  // Render: Error
  // -------------------------------------------------------------------------

  if (phase === "error" || !session) {
    return (
      <box
        flexDirection="column"
        width="100%"
        height="100%"
        alignItems="center"
        justifyContent="center"
        flexGrow={1}
        gap={2}
      >
        <text fg={colors.error}>Error: {error ?? "Session not found"}</text>
        <text fg={colors.textMuted}>Press ESC to return home</text>
      </box>
    );
  }

  // -------------------------------------------------------------------------
  // Render: Main view
  // -------------------------------------------------------------------------

  const isRunning = phase !== "loading" && phase !== "completed";

  return (
    <box flexDirection="column" width="100%" height="100%" flexGrow={1}>
      {/* Header */}
      <box
        width="100%"
        flexDirection="row"
        justifyContent="space-between"
        alignItems="center"
        padding={1}
        border={["bottom"]}
        borderColor={colors.primary}
      >
        <box flexDirection="row" gap={1}>
          {isRunning ? (
            <SpinnerDots
              label={`STRIDE Threat Model — ${phaseLabels[phase]}`}
              fg={colors.primary}
            />
          ) : (
            <text
              fg={phase === "completed" ? colors.primary : colors.textMuted}
            >
              {phase === "completed" ? "✓" : "●"} STRIDE Threat Model —{" "}
              {phaseLabels[phase]}
            </text>
          )}
        </box>
        <text fg={colors.textMuted}>{session.config?.cwd ?? ""}</text>
      </box>

      {/* Agent output */}
      <AgentDisplay
        messages={messages}
        isStreaming={isRunning}
        focused={true}
        paddingLeft={2}
        paddingRight={2}
        contextId="threat-model-logs"
      />

      {/* Completion banner */}
      {phase === "completed" && result && (
        <box
          width="100%"
          padding={1}
          backgroundColor={colors.backgroundElement}
          border
          borderColor={colors.primary}
          flexDirection="column"
          alignItems="center"
          gap={1}
        >
          <text fg={colors.primary}>STRIDE Threat Model Generated</text>
          <text fg={colors.textMuted}>{result.markdownPath}</text>
          <text fg={colors.textMuted}>{result.jsonPath}</text>
          <box flexDirection="row" gap={2}>
            <text>
              <span fg={colors.primary}>[Enter]</span>
              <span fg={colors.textMuted}> Open Report</span>
            </text>
            <text>
              <span fg={colors.primary}>[ESC]</span>
              <span fg={colors.textMuted}> Close</span>
            </text>
          </box>
        </box>
      )}

      {/* Footer */}
      <box
        width="100%"
        flexDirection="row"
        justifyContent="space-between"
        border={["top"]}
        borderColor={colors.primary}
        padding={1}
      >
        <box flexDirection="row" gap={2}>
          <text>
            <span fg={isRunning ? colors.primary : colors.textMuted}>
              {phaseLabels[phase]}
            </span>
          </text>
          <text fg={colors.textMuted}>|</text>
          <text>
            <span fg={colors.primary}>{messages.length}</span>
            <span fg={colors.textMuted}> messages</span>
          </text>
          {startTime && <ElapsedTime startTime={startTime} isRunning={isRunning} />}
        </box>
        <box flexDirection="row" gap={2}>
          <text>
            <span fg={colors.primary}>[ESC]</span>
            <span fg={colors.textMuted}> Back</span>
          </text>
        </box>
      </box>
    </box>
  );
}

// ---------------------------------------------------------------------------
// ElapsedTime
// ---------------------------------------------------------------------------

function ElapsedTime({
  startTime,
  isRunning,
}: {
  startTime: Date;
  isRunning: boolean;
}) {
  const { colors } = useTheme();
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    if (!isRunning) return;
    const interval = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(interval);
  }, [isRunning]);

  const duration = Math.floor((now - startTime.getTime()) / 1000);
  const mins = Math.floor(duration / 60);
  const secs = duration % 60;

  return (
    <>
      <text fg={colors.textMuted}>|</text>
      <text fg={colors.textMuted}>
        {mins}m {secs.toString().padStart(2, "0")}s
      </text>
    </>
  );
}
