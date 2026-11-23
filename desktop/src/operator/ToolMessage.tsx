import { Button } from "@pensarai/design-system/ui/button";
import { CodeBlockContent } from "@pensarai/design-system/ui/code-block";
import { Severity } from "@pensarai/design-system/ui/severity";
import { Spinner } from "@pensarai/design-system/ui/spinner";
import { Check, ChevronRight, ImageIcon, Layers, X } from "lucide-react";
import {
  type CSSProperties,
  memo,
  type ReactNode,
  useEffect,
  useId,
  useMemo,
  useState,
} from "react";
import WorkflowProgress from "../pentest/WorkflowProgress";
import type { OperatorMessage } from "./contract";
import { SubagentRows } from "./SubagentRows";
import { streamFadeDuration } from "./stream-fade";
import type { OperatorSubagent } from "./subagent-presentation";
import { toolIcon } from "./tool-icons";
import {
  asRecord,
  describeTool,
  formatToolData,
  segmentTools,
  type ToolPresentation,
  type ToolStatus,
  toolGroupDetail,
  toolGroupLabel,
  toolMessageKey,
} from "./tool-presentation";

const statusLabels: Record<ToolStatus, string> = {
  pending: "Preparing",
  running: "Running",
  completed: "Completed",
  error: "Failed",
  cancelled: "Cancelled",
  unknown: "Unknown status",
};

function DataBlock({ label, value }: { label: string; value: unknown }) {
  const [full, setFull] = useState(false);
  const text = useMemo(() => formatToolData(value), [value]);
  if (value === undefined) return null;
  const truncated = !full && text.length > 12_000;
  return (
    <div className="op-tool-data">
      <span className="op-tool-data-label">{label}</span>
      <CodeBlockContent className="op-tool-code">
        {truncated ? text.slice(0, 12_000) : text || "(empty)"}
      </CodeBlockContent>
      {text.length > 12_000 && (
        <Button size="xs" variant="ghost" onClick={() => setFull(!full)}>
          {full
            ? "Show preview"
            : `Show all ${text.length.toLocaleString()} characters`}
        </Button>
      )}
    </div>
  );
}

function Fields({ data }: { data: Record<string, unknown> }) {
  return (
    <dl className="op-tool-fields">
      {Object.entries(data).map(([key, value]) => (
        <div key={key}>
          <dt>
            {key.replace(/([a-z])([A-Z])/g, "$1 $2").replaceAll("_", " ")}
          </dt>
          <dd>
            {(typeof value === "object" && value !== null) ||
            (typeof value === "string" && value.length > 200) ? (
              <DataBlock label={key} value={value} />
            ) : (
              formatToolData(value)
            )}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function ToolOutput({ view }: { view: ToolPresentation }) {
  const input = asRecord(view.input) ?? {};
  const result = asRecord(view.output);
  const error = result?.error || result?.errorMessage;
  let body: ReactNode;
  if (
    view.kind === "command" &&
    result &&
    ("stdout" in result || "stderr" in result)
  ) {
    body = (
      <>
        {typeof result.jobId === "string" && (
          <DataBlock label="Job ID" value={result.jobId} />
        )}
        <DataBlock label="Output" value={result.stdout} />
        {result.stderr !== "" && (
          <DataBlock label="Standard error" value={result.stderr} />
        )}
      </>
    );
  } else if (
    view.kind === "http" &&
    result &&
    ("body" in result || "headers" in result)
  ) {
    body = (
      <>
        {result.headers !== undefined && (
          <details className="op-tool-extra">
            <summary>
              <ChevronRight className="op-tool-chevron" aria-hidden="true" />
              Response headers
            </summary>
            <Fields
              data={asRecord(result.headers) ?? { headers: result.headers }}
            />
          </details>
        )}
        <DataBlock label="Response body" value={result.body} />
      </>
    );
  } else if (
    view.kind === "file" &&
    (result?.content !== undefined ||
      input.content !== undefined ||
      input.oldString !== undefined ||
      input.old_string !== undefined)
  ) {
    body =
      input.oldString !== undefined || input.old_string !== undefined ? (
        <>
          <DataBlock
            label="Before"
            value={input.oldString ?? input.old_string}
          />
          <DataBlock
            label="After"
            value={input.newString ?? input.new_string}
          />
        </>
      ) : (
        <DataBlock label="Contents" value={result?.content ?? input.content} />
      );
  } else if (view.kind === "search" && Array.isArray(result?.results)) {
    body = (
      <div className="op-search-results">
        {result.results.map((entry, index) => {
          const item = asRecord(entry);
          if (!item)
            return (
              <DataBlock
                // biome-ignore lint/suspicious/noArrayIndexKey: Tool result entries are an immutable ordered snapshot without IDs.
                key={index}
                label={`Result ${index + 1}`}
                value={entry}
              />
            );
          return (
            // biome-ignore lint/suspicious/noArrayIndexKey: Tool result entries are an immutable ordered snapshot without IDs.
            <div key={index} className="op-search-result">
              {typeof item.title === "string" && <strong>{item.title}</strong>}
              {typeof item.url === "string" && (
                <span className="op-result-url">{item.url}</span>
              )}
              <DataBlock
                label="Preview"
                value={
                  item.snippet ??
                  item.description ??
                  item.text ??
                  item.content ??
                  item
                }
              />
            </div>
          );
        })}
      </div>
    );
  } else if (view.kind === "finding") {
    const severity =
      typeof input.severity === "string" ? input.severity.toLowerCase() : "";
    body = (
      <div className="op-tool-finding">
        {["critical", "high", "medium", "low", "info"].includes(severity) && (
          <Severity level={severity} />
        )}
        <Fields
          data={Object.fromEntries(
            Object.entries(input).filter(
              ([key]) => key !== "toolCallDescription" && key !== "severity",
            ),
          )}
        />
        {view.output !== undefined && (
          <DataBlock label="Result" value={view.output} />
        )}
      </div>
    );
  } else if (result) {
    const fields = Object.fromEntries(
      Object.entries(result).filter(
        ([key]) => !["success", "error", "errorMessage"].includes(key),
      ),
    );
    body = Object.keys(fields).length ? <Fields data={fields} /> : null;
  } else {
    body = <DataBlock label="Output" value={view.output} />;
  }
  return (
    <>
      {error ? <DataBlock label="Error" value={error} /> : null}
      {body}
    </>
  );
}

function RawToolData({ message }: { message: OperatorMessage }) {
  const [open, setOpen] = useState(false);
  return (
    <details
      className="op-tool-extra"
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary>
        <ChevronRight className="op-tool-chevron" aria-hidden="true" />
        Raw input and output
      </summary>
      {open && (
        <>
          <DataBlock label="Input" value={message.args} />
          <DataBlock label="Output" value={message.result} />
        </>
      )}
    </details>
  );
}

const ToolItem = memo(function ToolItem({
  message,
  onScreenshot,
}: {
  message: OperatorMessage;
  onScreenshot: (message: OperatorMessage) => void;
}) {
  const view = useMemo(() => describeTool(message), [message]);
  const input = asRecord(view.input);
  return (
    <div className="op-tool-item">
      {view.kind === "command" && input?.command !== undefined && (
        <DataBlock label="Command" value={input.command} />
      )}
      {view.kind !== "command" && view.kind !== "finding" && (
        <DataBlock
          label="Input"
          value={
            input
              ? Object.fromEntries(
                  Object.entries(input).filter(
                    ([key]) => key !== "toolCallDescription",
                  ),
                )
              : view.input
          }
        />
      )}
      {view.summary && <p className="op-tool-result-summary">{view.summary}</p>}
      {message.logs?.length ? (
        <DataBlock label="Execution log" value={message.logs.join("\n")} />
      ) : null}
      <ToolOutput view={view} />
      {message.toolName === "browser_screenshot" &&
        view.status === "completed" &&
        message.toolCallId && (
          <Button size="xs" onClick={() => onScreenshot(message)}>
            <ImageIcon className="op-tool-image-icon" aria-hidden="true" />
            View screenshot
          </Button>
        )}
      {view.output === undefined && !message.logs?.length && (
        <p className="op-tool-waiting">
          {view.status === "running" || view.status === "pending"
            ? "Waiting for output…"
            : "No output recorded."}
        </p>
      )}
      <RawToolData message={message} />
      <div className="op-tool-footer" data-status={view.status}>
        {view.status === "running" || view.status === "pending" ? (
          <Spinner
            className="op-tool-status-icon"
            aria-hidden="true"
            role={undefined}
            aria-label={undefined}
          />
        ) : view.status === "error" ? (
          <X aria-hidden="true" />
        ) : (
          <Check aria-hidden="true" />
        )}
        {statusLabels[view.status]}
      </div>
    </div>
  );
});

function RailRow({
  icon,
  label,
  object,
  meta,
  status,
  warning = false,
  open,
  panelId,
  onClick,
  arrival,
}: {
  icon: ReactNode;
  label: string;
  object?: string;
  meta?: string;
  status: ToolStatus;
  warning?: boolean;
  open: boolean;
  panelId: string;
  onClick: () => void;
  arrival?: number;
}) {
  const age = arrival ? performance.now() - arrival : streamFadeDuration;
  const style: CSSProperties | undefined =
    age < streamFadeDuration
      ? {
          animationDelay: `-${age}ms`,
        }
      : undefined;
  return (
    <button
      type="button"
      className="op-rail-row"
      style={style}
      data-arriving={age < streamFadeDuration}
      data-open={open}
      data-status={status}
      data-warning={warning}
      aria-expanded={open}
      aria-controls={open ? panelId : undefined}
      onClick={onClick}
    >
      <span className="op-rail-icon" aria-hidden="true">
        {icon}
      </span>
      <span className="op-rail-label" data-has-object={Boolean(object)}>
        {label}
      </span>
      {object && <span className="op-rail-object">{object}</span>}
      {meta && <span className="op-rail-meta">· {meta}</span>}
      <span className="sr-only">{statusLabels[status]}</span>
      <ChevronRight
        className="op-tool-chevron"
        data-open={open}
        aria-hidden="true"
      />
    </button>
  );
}

function RailLine() {
  return <span className="op-rail-line" aria-hidden="true" />;
}

export const ToolMessage = memo(
  function ToolMessage({
    items,
    verbose,
    onScreenshot,
    subagents,
    subagentsByTool,
    onSelectSubagent,
    arrivals,
    cancelCommandId,
    onCancelCommand,
    commandBusy,
  }: {
    items: OperatorMessage[];
    subagents?: OperatorSubagent[];
    subagentsByTool?: ReadonlyMap<string, OperatorSubagent[]>;
    onSelectSubagent?: (id: string) => void;
    arrivals?: ReadonlyMap<string | undefined, number>;
    cancelCommandId?: string;
    onCancelCommand?: (id: string) => void;
    commandBusy?: boolean;
    verbose: boolean;
    onScreenshot: (message: OperatorMessage) => void;
  }) {
    const id = useId();
    const [openTools, setOpenTools] = useState<Record<string, boolean>>({});
    const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({});
    useEffect(() => {
      const reset = (current: Record<string, boolean>) =>
        Object.fromEntries(Object.keys(current).map((key) => [key, verbose]));
      setOpenTools(reset);
      setOpenGroups(reset);
    }, [verbose]);
    const segments = useMemo(() => segmentTools(items), [items]);
    const keys = new Map(
      items.map((item, index) => [item, toolMessageKey(item, index)]),
    );
    const messageKey = (message: OperatorMessage) => {
      const key = keys.get(message);
      if (key === undefined)
        throw new Error("Tool is missing from its transcript rail");
      return key;
    };
    const toolOpen = (message: OperatorMessage) =>
      openTools[messageKey(message)] ??
      (verbose ||
        (message.toolName === "browser_screenshot" &&
          message.status === "completed" &&
          Boolean(message.toolCallId)));
    const cancelButton = (toolCallId?: string) =>
      toolCallId && toolCallId === cancelCommandId && onCancelCommand ? (
        <Button
          variant="ghost"
          size="xs"
          className="op-command-cancel"
          disabled={commandBusy}
          onClick={() => onCancelCommand(toolCallId)}
        >
          <X size={12} aria-hidden="true" /> Cancel command
        </Button>
      ) : null;
    const renderTool = (message: OperatorMessage) => {
      const key = messageKey(message);
      const view = describeTool(message);
      const Icon = toolIcon(message.toolName ?? "tool");
      const open = toolOpen(message);
      const panelId = `${id}-tool-${key}`;
      const children = message.toolCallId
        ? subagentsByTool?.get(message.toolCallId)
        : undefined;
      return (
        <div
          className="op-rail-entry"
          key={key}
          data-tool-id={message.toolCallId}
        >
          <div className="op-tool-row">
            <RailRow
              arrival={arrivals?.get(message.toolCallId)}
              icon={
                view.status === "running" || view.status === "pending" ? (
                  <Spinner
                    className="op-tool-status-icon"
                    role={undefined}
                    aria-label={undefined}
                  />
                ) : (
                  <Icon />
                )
              }
              label={view.headline}
              status={view.status}
              open={open}
              panelId={panelId}
              meta={view.status === "error" ? "Failed" : undefined}
              onClick={() =>
                setOpenTools((current) => ({ ...current, [key]: !open }))
              }
            />
            {cancelButton(message.toolCallId)}
          </div>
          {open && (
            <div className="op-tool-panel" id={panelId}>
              <div className="op-tool-panel-kind">
                {view.kind === "command"
                  ? "Command"
                  : view.kind === "http"
                    ? "HTTP request"
                    : "Tool call"}
              </div>
              <ToolItem message={message} onScreenshot={onScreenshot} />
            </div>
          )}
          {children?.length && subagents && onSelectSubagent ? (
            <div className="op-tool-children">
              <SubagentRows
                agents={children}
                allAgents={subagents}
                onSelect={onSelectSubagent}
              />
            </div>
          ) : null}
          {message.workflowData && (
            <div className="op-tool-workflow">
              <WorkflowProgress data={message.workflowData} />
            </div>
          )}
        </div>
      );
    };
    return (
      <div className="op-tool op-tool-rail" aria-label="Tool activity">
        <RailLine />
        {segments.map((segment) => {
          if (!segment.family) return renderTool(segment.items[0]);
          const key = `${segment.family}-${segment.key}`;
          const open =
            openGroups[key] ?? (verbose || segment.items.some(toolOpen));
          const views = segment.items.map(describeTool);
          const running = views.some(
            (view) => view.status === "running" || view.status === "pending",
          );
          const failures = views.filter(
            (view) => view.status === "error",
          ).length;
          const status = running
            ? "running"
            : failures
              ? "error"
              : (views.find((view) => view.status !== "completed")?.status ??
                "completed");
          const Icon =
            segment.family === "repository"
              ? Layers
              : toolIcon(segment.items[0].toolName ?? "tool");
          const panelId = `${id}-group-${key}`;
          const meta = [
            segment.family === "repository"
              ? `${segment.items.length} steps`
              : "",
            failures ? `${failures} failed` : "",
          ]
            .filter(Boolean)
            .join(" · ");
          return (
            <div
              className="op-rail-group"
              key={key}
              data-family={segment.family}
            >
              <div className="op-tool-row">
                <RailRow
                  arrival={arrivals?.get(segment.items[0].toolCallId)}
                  icon={
                    running && segment.family !== "repository" ? (
                      <Spinner
                        className="op-tool-status-icon"
                        role={undefined}
                        aria-label={undefined}
                      />
                    ) : (
                      <Icon />
                    )
                  }
                  label={toolGroupLabel(segment.family, segment.items.length)}
                  object={
                    segment.family === "repository"
                      ? toolGroupDetail(segment.items)
                      : undefined
                  }
                  meta={meta}
                  status={status}
                  warning={failures > 0}
                  open={open}
                  panelId={panelId}
                  onClick={() =>
                    setOpenGroups((current) => ({ ...current, [key]: !open }))
                  }
                />
                {!open &&
                  segment.items.some(
                    (item) => item.toolCallId === cancelCommandId,
                  ) &&
                  cancelButton(cancelCommandId)}
              </div>
              {open && (
                <div className="op-tool-rail op-rail-nested" id={panelId}>
                  <RailLine />
                  {segment.items.map(renderTool)}
                </div>
              )}
            </div>
          );
        })}
      </div>
    );
  },
  (previous, next) =>
    previous.cancelCommandId === next.cancelCommandId &&
    previous.onCancelCommand === next.onCancelCommand &&
    previous.commandBusy === next.commandBusy &&
    previous.arrivals === next.arrivals &&
    previous.subagents === next.subagents &&
    previous.subagentsByTool === next.subagentsByTool &&
    previous.onSelectSubagent === next.onSelectSubagent &&
    previous.verbose === next.verbose &&
    previous.onScreenshot === next.onScreenshot &&
    previous.items.length === next.items.length &&
    previous.items.every((item, index) => item === next.items[index]),
);
