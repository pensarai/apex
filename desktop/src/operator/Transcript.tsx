import { Button } from "@pensarai/design-system/ui/button";
import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { ActivityIndicator } from "./ActivityIndicator";
import type { OperatorClient } from "./client";
import type { OperatorActivity, OperatorMessage } from "./contract";
import { MessageCopy } from "./MessageCopy";
import { ReasoningMessage } from "./ReasoningMessage";
import { StreamingMarkdown } from "./StreamingMarkdown";
import { SubagentRows } from "./SubagentRows";
import { groupSubagents, type OperatorSubagent } from "./subagent-presentation";
import { ToolMessage } from "./ToolMessage";
import { groupTranscript } from "./tool-presentation";

const noSubagents: OperatorSubagent[] = [];

export function Transcript({
  messages,
  screenshot: loadScreenshot,
  visible,
  sessionId,
  agentId,
  verbose,
  activity,
  modelLoading,
  subagents = noSubagents,
  onSelectSubagent,
  cancelCommandId,
  onCancelCommand,
  commandBusy,
}: {
  messages: OperatorMessage[];
  screenshot: OperatorClient["operatorScreenshot"];
  visible: boolean;
  sessionId: string;
  agentId?: string;
  verbose: boolean;
  activity?: OperatorActivity;
  modelLoading?: string;
  subagents?: OperatorSubagent[];
  onSelectSubagent?: (id: string) => void;
  cancelCommandId?: string;
  onCancelCommand?: (id: string) => void;
  commandBusy?: boolean;
}) {
  const box = useRef<HTMLDivElement>(null);
  const follow = useRef(true);
  const scrollPosition = useRef(0);
  const [screenshot, setScreenshot] = useState("");
  const [error, setError] = useState("");
  const rows = useMemo(() => groupTranscript(messages), [messages]);
  const initialRows = useRef(new Set(rows.map((row) => row.key)));
  const seenTools = useRef(
    new Map(messages.map((message) => [message.toolCallId, 0])),
  );
  const toolArrivals = useMemo(() => {
    let next = seenTools.current;
    for (const message of messages) {
      if (message.toolCallId && !next.has(message.toolCallId)) {
        if (next === seenTools.current) next = new Map(next);
        next.set(message.toolCallId, visible ? performance.now() : 0);
      }
    }
    return next;
  }, [messages, visible]);
  useLayoutEffect(() => {
    seenTools.current = toolArrivals;
  }, [toolArrivals]);
  const children = useMemo(
    () => groupSubagents(messages, subagents),
    [messages, subagents],
  );
  const showScreenshot = useCallback(
    (message: OperatorMessage) => {
      if (!message.toolCallId) return;
      setError("");
      void loadScreenshot({
        sessionId,
        toolCallId: message.toolCallId,
        agentId,
      })
        .then(setScreenshot)
        .catch((e) => setError(String(e)));
    },
    [loadScreenshot, sessionId, agentId],
  );
  useLayoutEffect(() => {
    if (visible && box.current && !follow.current)
      box.current.scrollTop = scrollPosition.current;
  }, [visible]);
  useEffect(() => {
    if (
      visible &&
      (messages.length || subagents.length || activity) &&
      follow.current &&
      box.current
    )
      box.current.scrollTop = box.current.scrollHeight;
  }, [messages, activity, visible, subagents]);
  return (
    <div
      className="op-transcript"
      ref={box}
      role="log"
      aria-label={agentId ? "Subagent conversation" : "Operator conversation"}
      onScroll={(e) => {
        if (!visible) return;
        const el = e.currentTarget;
        scrollPosition.current = el.scrollTop;
        follow.current = el.scrollHeight - el.scrollTop - el.clientHeight < 48;
      }}
    >
      {!messages.length && !activity && (
        <p className="op-empty">
          {agentId
            ? "No messages were recorded for this subagent."
            : "Send an objective to begin the conversation."}
        </p>
      )}
      {rows.map((row) => {
        if (row.kind === "tools")
          return (
            <ToolMessage
              key={row.key}
              items={row.items}
              verbose={verbose}
              onScreenshot={showScreenshot}
              subagents={subagents}
              subagentsByTool={children.byTool}
              onSelectSubagent={onSelectSubagent}
              arrivals={toolArrivals}
              cancelCommandId={cancelCommandId}
              onCancelCommand={onCancelCommand}
              commandBusy={commandBusy}
            />
          );
        const message = row.message;
        if (!message.content.trim() && !message.reasoning) return null;
        return (
          <article
            key={row.key}
            className={`op-turn op-turn-${message.role}`}
            aria-label={
              message.role === "user"
                ? "You"
                : message.role === "assistant"
                  ? "Apex"
                  : "System"
            }
          >
            {message.reasoning && (
              <ReasoningMessage reasoning={message.reasoning} />
            )}
            {message.role === "assistant" ? (
              <StreamingMarkdown
                text={message.content}
                visible={visible}
                fresh={!initialRows.current.has(row.key)}
              />
            ) : (
              <div className="op-text">{message.content}</div>
            )}
            {message.content.trim() && <MessageCopy text={message.content} />}
          </article>
        );
      })}
      {!agentId && children.unlinked.length > 0 && onSelectSubagent && (
        <section className="op-unlinked-subagents">
          <h3>Subagents</h3>
          <SubagentRows
            agents={children.unlinked}
            allAgents={subagents}
            onSelect={onSelectSubagent}
          />
        </section>
      )}
      {activity &&
        !(
          activity === "thinking" &&
          messages.some(
            (message) => message.reasoning && !message.reasoning.complete,
          )
        ) && (
          <ActivityIndicator activity={activity} modelLoading={modelLoading} />
        )}
      {error && <p role="alert">{error}</p>}
      {visible && screenshot && (
        <dialog open className="op-image">
          <Button size="sm" onClick={() => setScreenshot("")}>
            Close screenshot
          </Button>
          <img src={screenshot} alt="Screenshot captured by the browser tool" />
        </dialog>
      )}
    </div>
  );
}
