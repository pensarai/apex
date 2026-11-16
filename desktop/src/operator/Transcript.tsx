import { Button } from "@pensarai/design-system/ui/button";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { LocalMarkdown } from "../view/LocalMarkdown";
import { ActivityIndicator } from "./ActivityIndicator";
import type { OperatorClient } from "./client";
import type { OperatorActivity, OperatorMessage } from "./contract";
import { ToolMessage } from "./ToolMessage";
import { groupTranscript } from "./tool-presentation";

export function Transcript({
  messages,
  screenshot: loadScreenshot,
  visible,
  sessionId,
  agentId,
  verbose,
  activity,
  modelLoading,
}: {
  messages: OperatorMessage[];
  screenshot: OperatorClient["operatorScreenshot"];
  visible: boolean;
  sessionId: string;
  agentId?: string;
  verbose: boolean;
  activity?: OperatorActivity;
  modelLoading?: string;
}) {
  const box = useRef<HTMLDivElement>(null);
  const follow = useRef(true);
  const [screenshot, setScreenshot] = useState("");
  const [error, setError] = useState("");
  const rows = useMemo(() => groupTranscript(messages), [messages]);
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
  useEffect(() => {
    if (
      visible &&
      (messages.length || activity) &&
      follow.current &&
      box.current
    )
      box.current.scrollTop = box.current.scrollHeight;
  }, [messages, activity, visible]);
  return (
    <div
      className="op-transcript"
      ref={box}
      role="log"
      aria-label={agentId ? "Subagent conversation" : "Operator conversation"}
      onScroll={(e) => {
        const el = e.currentTarget;
        follow.current = el.scrollHeight - el.scrollTop - el.clientHeight < 48;
      }}
    >
      {!messages.length && !activity && (
        <p className="op-empty">Send an objective to begin the conversation.</p>
      )}
      {rows.map((row) => {
        if (row.kind === "tools")
          return (
            <ToolMessage
              key={row.key}
              items={row.items}
              verbose={verbose}
              onScreenshot={showScreenshot}
            />
          );
        const message = row.message;
        if (!message.content.trim()) return null;
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
            {message.role === "assistant" ? (
              <LocalMarkdown text={message.content} />
            ) : (
              <div className="op-text">{message.content}</div>
            )}
          </article>
        );
      })}
      {activity && (
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
