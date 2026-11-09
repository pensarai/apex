import { Button } from "@pensarai/design-system/ui/button";
import { useEffect, useRef, useState } from "react";
import WorkflowProgress from "../pentest/WorkflowProgress";
import { api } from "../view/bridge";
import { LocalMarkdown } from "../view/LocalMarkdown";
import type { OperatorMessage } from "./contract";

export function Transcript({
  messages,
  sessionId,
  agentId,
  verbose,
}: {
  messages: OperatorMessage[];
  sessionId: string;
  agentId?: string;
  verbose: boolean;
}) {
  const box = useRef<HTMLDivElement>(null);
  const follow = useRef(true);
  const [screenshot, setScreenshot] = useState("");
  const [error, setError] = useState("");
  useEffect(() => {
    if (messages.length && follow.current && box.current)
      box.current.scrollTop = box.current.scrollHeight;
  }, [messages]);
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
      {!messages.length && (
        <p className="op-empty">Send an objective to begin the conversation.</p>
      )}
      {messages.map((m, i) => (
        <article
          key={m.toolCallId ?? `${m.role}-${m.createdAt}-${i}`}
          className={m.role === "tool" ? "op-tool" : "op-turn"}
        >
          {m.role === "tool" ? (
            <>
              <details key={String(verbose)} open={verbose || undefined}>
                <summary>
                  <span>{m.toolName}</span>
                  <small>{m.status}</small>
                </summary>
                {m.args !== undefined && (
                  <pre>{JSON.stringify(m.args, null, 2)}</pre>
                )}
                {m.logs?.length ? <pre>{m.logs.join("\n")}</pre> : null}
                {m.result !== undefined && (
                  <pre>
                    {typeof m.result === "string"
                      ? m.result
                      : JSON.stringify(m.result, null, 2)}
                  </pre>
                )}
              </details>
              {m.workflowData && <WorkflowProgress data={m.workflowData} />}
              {m.toolName === "browser_screenshot" &&
                m.status === "completed" && (
                  <Button
                    size="xs"
                    onClick={() => {
                      if (!m.toolCallId) return;
                      void api
                        .operatorScreenshot({
                          sessionId,
                          toolCallId: m.toolCallId,
                          agentId,
                        })
                        .then(setScreenshot)
                        .catch((e) => setError(String(e)));
                    }}
                  >
                    View screenshot
                  </Button>
                )}
            </>
          ) : (
            <>
              <small>{m.role}</small>
              {m.role === "assistant" ? (
                <LocalMarkdown text={m.content} />
              ) : (
                <div className="op-text">{m.content}</div>
              )}
            </>
          )}
        </article>
      ))}
      {error && <p role="alert">{error}</p>}
      {screenshot && (
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
