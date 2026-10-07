import { readFile } from "node:fs/promises";
import type { RGBA, ScrollBoxRenderable } from "@opentui/core";
import { useKeyboard } from "@opentui/react";
import type { ModelMessage } from "ai";
import { useEffect, useRef, useState } from "react";
import type { WorkerExecutable } from "../../../core/runtime/launchLocalWorker";
import {
  openRecordedRunClient,
  type RecordedRunView,
} from "../../../core/runtime/recordedRunClient";
import type { RunRecord } from "../../../core/runtime/runStore";
import { useDimensions } from "../../context/dimensions";
import { type ThemeColors, useTheme } from "../../theme";
import DialogLayout from "../dialog-layout";

type RunClient = Awaited<ReturnType<typeof openRecordedRunClient>>;

export interface RecordedRunsDialogProps {
  /** Open this run directly; omitted opens the run list. */
  runId?: string;
  /** Optional explicit store path; defaults like the SQLite store. */
  databasePath?: string;
  /** Start a detached run once from this spec file, then follow it. */
  specPath?: string;
  /** CLI entry that re-enters `agent-runs worker` for this package. */
  executable: WorkerExecutable;
}

const CONNECTION_LABELS = {
  connected: "live",
  offline: "offline — a foreground executor may still exist",
  error: "endpoint error",
} as const;

function shortId(id: string): string {
  return id.length > 18 ? `${id.slice(0, 15)}…` : id;
}

function formatInput(input: unknown): string {
  try {
    return JSON.stringify(input, null, 2) ?? "null";
  } catch {
    return String(input);
  }
}

function transcriptLine(message: ModelMessage): string {
  if (typeof message.content === "string") return message.content;
  return message.content
    .map((part) => {
      if (part.type === "text") return part.text;
      if (part.type === "tool-call")
        return `${part.toolName}: ${formatInput(part.input)}`;
      if (part.type === "tool-result")
        return `${part.toolName}: ${formatInput(part.output)}`;
      return `[${part.type}]`;
    })
    .join("\n");
}

function statusColor(status: RunRecord["status"], colors: ThemeColors): RGBA {
  if (status === "completed") return colors.success;
  if (status === "running") return colors.warning;
  if (status === "failed") return colors.error;
  return colors.textMuted;
}

function connectionColor(
  connection: RecordedRunView["connection"],
  colors: ThemeColors,
): RGBA {
  if (connection === "connected") return colors.success;
  if (connection === "offline") return colors.textMuted;
  return colors.error;
}

function workerErrorText(view: RecordedRunView): string | null {
  if (!view.worker?.error) return null;
  return [view.worker.error.message, ...(view.worker.error.blockers ?? [])]
    .filter(Boolean)
    .join("\n");
}

export function RecordedRunsDialog({
  runId,
  databasePath,
  specPath,
  executable,
}: RecordedRunsDialogProps) {
  const { colors } = useTheme();
  const dimensions = useDimensions();
  const [client, setClient] = useState<RunClient | null>(null);
  const [openError, setOpenError] = useState<string | null>(null);
  const [page, setPage] = useState<"list" | "detail">(
    runId || specPath ? "detail" : "list",
  );
  const [runs, setRuns] = useState<RunRecord[]>([]);
  const [listRevision, setListRevision] = useState(0);
  const [listError, setListError] = useState<string | null>(null);
  // Selection identity is the run id: a refreshed list inserting or removing
  // rows cannot move the highlight off the operator's run.
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [view, setView] = useState<RecordedRunView | null>(null);
  const [viewRunId, setViewRunId] = useState<string | null>(runId ?? null);
  const [following, setFollowing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [statusLine, setStatusLine] = useState<string | null>(null);
  // Worker retirement must not erase recovery blockers from the view.
  const [stickyError, setStickyError] = useState<string | null>(null);
  const [selectedApprovalIndex, setSelectedApprovalIndex] = useState(0);

  const startedOnce = useRef(false);
  const detailScroll = useRef<ScrollBoxRenderable>(null);
  const listScroll = useRef<ScrollBoxRenderable>(null);
  const actionPending = useRef(false);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  // Async spec startup must not replace the operator's navigation.
  const navigationChanged = useRef(false);
  // Null means no run is anchored yet (first row); an id whose run vanished
  // from the refreshed list falls back to the first row.
  const selectedIndex =
    selectedRunId === null
      ? 0
      : Math.max(
          0,
          runs.findIndex((record) => record.spec.runId === selectedRunId),
        );
  useEffect(() => {
    const selected = runs[selectedIndex];
    if (selected)
      listScroll.current?.scrollChildIntoView(
        `recorded-${selected.spec.runId}`,
      );
  }, [runs, selectedIndex]);

  // Closing while the store opens must still release the eventual client.
  useEffect(() => {
    let cancelled = false;
    let owned: RunClient | null = null;
    openRecordedRunClient(databasePath)
      .then((opened) => {
        if (cancelled) {
          void opened.close().catch(() => {
            // The dialog is already gone; never let cleanup reject globally.
          });
          return;
        }
        owned = opened;
        setClient(opened);
      })
      .catch((cause: unknown) => {
        if (!cancelled) {
          setOpenError(cause instanceof Error ? cause.message : String(cause));
        }
      });
    return () => {
      cancelled = true;
      void owned?.close().catch(() => {
        // Cleanup cannot report into a dismissed dialog.
      });
    };
  }, [databasePath]);

  useEffect(() => {
    if (!client || page !== "detail" || !viewRunId) return;
    const controller = new AbortController();
    setFollowing(true);
    const loop = (async () => {
      try {
        for await (const next of client.watch(viewRunId, controller.signal)) {
          if (controller.signal.aborted) return;
          setView(next);
          const errorText = workerErrorText(next);
          if (errorText) setStickyError(errorText);
        }
      } catch (cause) {
        if (!controller.signal.aborted) {
          setStickyError(
            cause instanceof Error ? cause.message : String(cause),
          );
        }
      } finally {
        if (!controller.signal.aborted) setFollowing(false);
      }
    })();
    return () => {
      controller.abort();
      void loop; // The loop handles abort and failures before it settles.
    };
  }, [client, page, viewRunId]);

  // Spec start happens exactly once and is never retried here.
  useEffect(() => {
    if (!client || !specPath || startedOnce.current) return;
    startedOnce.current = true;
    void (async () => {
      try {
        const spec = JSON.parse(await readFile(specPath, "utf8"));
        if (!mounted.current) return;
        const started = await client.start(spec, executable);
        if (!mounted.current) return;
        setStatusLine(
          `Started detached run ${started.snapshot.runId} (log: ${started.logPath})`,
        );
        if (!navigationChanged.current) {
          setViewRunId(started.snapshot.runId);
        }
      } catch (cause) {
        if (!mounted.current) return;
        setStickyError(
          `Start failed: ${cause instanceof Error ? cause.message : String(cause)}`,
        );
        if (!navigationChanged.current) setPage("list");
      } finally {
        if (mounted.current) setListRevision((revision) => revision + 1);
      }
    })();
  }, [client, specPath, executable]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: listRevision refreshes an open list when spec startup settles.
  useEffect(() => {
    if (!client || page !== "list") return;
    let cancelled = false;
    client
      .list()
      .then((records) => {
        if (cancelled) return;
        setRuns(records);
        // Anchor the default selection once and replace an id whose run
        // vanished, so the state always names a listed run.
        setSelectedRunId((current) => {
          if (
            current !== null &&
            records.some((record) => record.spec.runId === current)
          )
            return current;
          return records[0]?.spec.runId ?? null;
        });
        setListError(null);
      })
      .catch((cause: unknown) => {
        if (!cancelled)
          setListError(cause instanceof Error ? cause.message : String(cause));
      });
    return () => {
      cancelled = true;
    };
  }, [client, page, listRevision]);

  const openRun = (targetRun: string) => {
    navigationChanged.current = true;
    setView(null);
    setStickyError(null);
    setStatusLine(null);
    setSelectedApprovalIndex(0);
    setPage("detail");
    setViewRunId(targetRun);
  };

  const backToList = () => {
    navigationChanged.current = true;
    setViewRunId(null);
    setView(null);
    setStickyError(null);
    setStatusLine(null);
    setPage("list");
  };

  const act = async (
    action: string,
    run: (opened: RunClient) => Promise<string>,
  ) => {
    if (!client || actionPending.current || !view) return;
    actionPending.current = true;
    setBusy(true);
    setStickyError(null);
    setStatusLine(null);
    try {
      const result = await run(client);
      if (mounted.current) setStatusLine(result);
    } catch (cause) {
      if (!mounted.current) return;
      setStickyError(
        `${action} failed: ${cause instanceof Error ? cause.message : String(cause)}`,
      );
    } finally {
      actionPending.current = false;
      if (mounted.current) setBusy(false);
    }
  };

  useKeyboard(async (key) => {
    if (key.name === "escape" || busy) return;
    const { ctrl, meta } = key;
    if (ctrl || meta) return;
    if (
      [
        "up",
        "down",
        "return",
        "b",
        "p",
        "s",
        "r",
        "y",
        "n",
        "pageup",
        "pagedown",
        "home",
        "end",
      ].includes(key.name)
    )
      key.preventDefault();
    if (
      page === "detail" &&
      ["pageup", "pagedown", "home", "end"].includes(key.name)
    ) {
      const scroll = detailScroll.current;
      if (key.name === "home") scroll?.scrollTo(0);
      else if (key.name === "end") scroll?.scrollTo(scroll.scrollHeight);
      else scroll?.scrollBy(key.name === "pageup" ? -1 : 1, "viewport");
      return;
    }

    if (page === "list") {
      if ((key.name === "up" || key.name === "down") && runs.length > 0) {
        const direction = key.name === "down" ? 1 : -1;
        // Functional update: queued key events advance from the latest
        // selection, not the one this render shows.
        setSelectedRunId((current) => {
          const index =
            current === null
              ? 0
              : Math.max(
                  0,
                  runs.findIndex((record) => record.spec.runId === current),
                );
          return (
            runs[(index + direction + runs.length) % runs.length]?.spec.runId ??
            null
          );
        });
        return;
      }
      if (key.name === "return" && runs.length > 0) {
        const target = runs[selectedIndex];
        if (target) openRun(target.spec.runId);
      }
      return;
    }

    if (key.name === "b") {
      backToList();
      return;
    }

    const pendingApprovals = (view?.observation.approvals ?? []).filter(
      (approval) => approval.state === "pending",
    );

    if (key.name === "up" && pendingApprovals.length > 0) {
      setSelectedApprovalIndex((index) =>
        index > 0 ? index - 1 : pendingApprovals.length - 1,
      );
      return;
    }
    if (key.name === "down" && pendingApprovals.length > 0) {
      setSelectedApprovalIndex((index) =>
        index < pendingApprovals.length - 1 ? index + 1 : 0,
      );
      return;
    }

    if (key.name === "p" && view?.observation.control) {
      const control = view.observation.control;
      await act("Pause", async (opened) => {
        await opened.requestControl(view.runId, "pause", control.revision);
        return "Pause requested";
      });
      return;
    }
    if (key.name === "s" && view?.observation.control) {
      const control = view.observation.control;
      await act("Stop", async (opened) => {
        await opened.requestControl(view.runId, "stop", control.revision);
        return "Stop requested";
      });
      return;
    }
    if (key.name === "r" && view?.observation.record) {
      const record = view.observation.record;
      await act("Resume", async (opened) => {
        await opened.resume(view.runId, record.attemptId, executable);
        return "Resume requested";
      });
      return;
    }

    const selected =
      pendingApprovals[
        Math.min(
          selectedApprovalIndex,
          Math.max(0, pendingApprovals.length - 1),
        )
      ];
    if (!selected || !view) return;
    if (key.name === "y") {
      await act("Approve", async (opened) => {
        await opened.resolveApproval(
          view.runId,
          selected.approvalId,
          "approved",
        );
        return `Approved ${selected.toolName}`;
      });
      return;
    }
    if (key.name === "n") {
      await act("Reject", async (opened) => {
        await opened.resolveApproval(view.runId, selected.approvalId, "denied");
        return `Rejected ${selected.toolName}`;
      });
    }
  });

  if (openError) {
    return (
      <DialogLayout title="Recorded Runs" escLabel={null}>
        <text fg={colors.error}>Cannot open the run store: {openError}</text>
      </DialogLayout>
    );
  }

  if (page === "list") {
    return (
      <DialogLayout
        title="Recorded Runs"
        footerActions={[
          { key: "Enter", label: "attach", variant: "primary" as const },
        ]}
      >
        {stickyError && <text fg={colors.error}>{stickyError}</text>}
        {listError && <text fg={colors.error}>List failed: {listError}</text>}
        {statusLine && <text fg={colors.textMuted}>{statusLine}</text>}
        {!client && <text fg={colors.textMuted}>Opening run store…</text>}
        {client && runs.length === 0 && !listError && (
          <text fg={colors.textMuted}>No recorded runs found.</text>
        )}
        <text fg={colors.textMuted}>
          Saved status · worker connection is checked when attached
        </text>
        <scrollbox
          ref={listScroll}
          height={Math.max(
            1,
            Math.min(runs.length + 1, dimensions.height - 13),
          )}
          scrollY
          scrollX={false}
          scrollbarOptions={{
            trackOptions: {
              foregroundColor: colors.textMuted,
              backgroundColor: colors.backgroundElement,
            },
          }}
        >
          {runs.map((record, index) => {
            const selected = index === selectedIndex;
            return (
              <box
                id={`recorded-${record.spec.runId}`}
                key={record.spec.runId}
                flexDirection="row"
                width="100%"
              >
                <text
                  fg={selected ? colors.primary : colors.text}
                  {...(selected
                    ? { backgroundColor: colors.backgroundSelected }
                    : {})}
                >
                  {`${selected ? "› " : "  "}${record.spec.runId}`}
                </text>
                <text fg={statusColor(record.status, colors)}>
                  {`  ${record.status}`}
                </text>
                <text fg={colors.textMuted}>{`  ${record.spec.model}`}</text>
              </box>
            );
          })}
        </scrollbox>
      </DialogLayout>
    );
  }

  const record = view?.observation.record ?? null;
  const control = view?.observation.control ?? null;
  const context = view?.observation.context ?? null;
  const approvals = view?.observation.approvals ?? [];
  const pendingApprovals = approvals.filter(
    (approval) => approval.state === "pending",
  );
  const decidedCount = approvals.length - pendingApprovals.length;
  const selectedApproval =
    pendingApprovals[
      Math.min(selectedApprovalIndex, Math.max(0, pendingApprovals.length - 1))
    ];
  const connection = view?.connection ?? "offline";

  const footer = [
    ...(pendingApprovals.length > 0
      ? [
          { key: "Y", label: "approve", variant: "primary" as const },
          { key: "N", label: "reject", variant: "danger" as const },
        ]
      : []),
    { key: "P", label: "pause" },
    { key: "R", label: "resume" },
    { key: "S", label: "stop", variant: "danger" as const },
    { key: "B", label: "list" },
    { key: "PgUp/PgDn", label: "scroll" },
  ];

  return (
    <DialogLayout
      title={`Recorded Run ${viewRunId ?? "…"}`}
      footerActions={footer}
    >
      <scrollbox
        ref={detailScroll}
        height={Math.max(1, dimensions.height - 12)}
        scrollY
        scrollX={false}
        scrollbarOptions={{
          trackOptions: {
            foregroundColor: colors.textMuted,
            backgroundColor: colors.backgroundElement,
          },
        }}
      >
        {!client && <text fg={colors.textMuted}>Opening run store…</text>}
        {client && !view && !stickyError && (
          <text fg={colors.textMuted}>Reading committed state…</text>
        )}
        {stickyError && <text fg={colors.error}>{stickyError}</text>}
        {statusLine && <text fg={colors.success}>{statusLine}</text>}
        {view && (
          <box flexDirection="column" width="100%" overflow="hidden">
            <box flexDirection="row" width="100%" flexShrink={0}>
              <text fg={connectionColor(connection, colors)}>
                {CONNECTION_LABELS[connection]}
              </text>
              <text fg={colors.textMuted}>
                {following ? " · following" : " · not following"}
                {view.worker ? ` · worker ${view.worker.phase}` : ""}
              </text>
            </box>
            {view.error && <text fg={colors.error}>{view.error}</text>}
            {record ? (
              <text fg={colors.text}>
                {`Saved status: ${record.status}`}
                {busy ? " · acting…" : ""}
                {` · attempt ${shortId(record.attemptId)}`}
                {` · model ${record.spec.model}`}
              </text>
            ) : (
              <text fg={colors.warning}>
                No saved record — the run id may not exist yet.
              </text>
            )}
            {control && (
              <text fg={colors.textMuted}>
                {`Control ${control.intent} · revision ${control.revision}`}
              </text>
            )}
            {context ? (
              <text fg={colors.textMuted}>
                {`Context epoch ${context.epoch} · revision ${context.revision} · ${context.messages.length} messages`}
              </text>
            ) : (
              <text fg={colors.textMuted}>No committed context yet.</text>
            )}

            <box
              flexDirection="column"
              width="100%"
              marginTop={1}
              overflow="hidden"
            >
              <text fg={colors.text}>
                {`Pending decisions (${pendingApprovals.length}, decided ${decidedCount})`}
              </text>
              {pendingApprovals.length > 0 ? (
                <>
                  {pendingApprovals.map((approval) => {
                    const selected =
                      approval.approvalId === selectedApproval?.approvalId;
                    return (
                      <text
                        key={approval.approvalId}
                        fg={selected ? colors.primary : colors.text}
                        {...(selected
                          ? { backgroundColor: colors.backgroundSelected }
                          : {})}
                      >
                        {`${selected ? "› " : "  "}${approval.toolName} (${shortId(approval.toolCallId)})`}
                      </text>
                    );
                  })}
                  {selectedApproval && (
                    <box
                      flexDirection="column"
                      width="100%"
                      marginTop={1}
                      borderStyle="rounded"
                      borderColor={colors.borderSubtle}
                    >
                      <text fg={colors.textMuted}>
                        {`Selected input — ${selectedApproval.toolName} · ${shortId(selectedApproval.approvalId)}`}
                      </text>
                      <text fg={colors.text}>
                        {formatInput(selectedApproval.input)}
                      </text>
                    </box>
                  )}
                </>
              ) : (
                <text fg={colors.textMuted}>Nothing awaiting a decision.</text>
              )}
            </box>
            {context && (
              <box
                flexDirection="column"
                width="100%"
                marginTop={1}
                overflow="hidden"
                borderStyle="rounded"
                borderColor={colors.borderSubtle}
              >
                <text fg={colors.textMuted}>Saved transcript (committed)</text>
                {context.messages.map((message, index) => (
                  <text
                    // biome-ignore lint/suspicious/noArrayIndexKey: each committed snapshot is a full replacement; repeated messages are valid.
                    key={`${message.role}-${index}`}
                    fg={
                      message.role === "user" ? colors.text : colors.textMuted
                    }
                  >
                    {`${message.role.padEnd(9)} ${transcriptLine(message)}`}
                  </text>
                ))}
              </box>
            )}
          </box>
        )}
      </scrollbox>
    </DialogLayout>
  );
}
