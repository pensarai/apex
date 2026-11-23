import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@pensarai/design-system/ui/accordion";
import { Button } from "@pensarai/design-system/ui/button";
import { Input } from "@pensarai/design-system/ui/input";
import { Severity } from "@pensarai/design-system/ui/severity";
import { RefreshCw, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import type { FindingRow } from "../shared";
import { api } from "../view/bridge";
import { LocalMarkdown } from "../view/LocalMarkdown";
import "./issues.css";

const severityOrder = ["critical", "high", "medium", "low"];
const severityRank = (severity: string) => {
  const index = severityOrder.indexOf(severity?.toLowerCase());
  return index < 0 ? severityOrder.length : index;
};

export function Issues({
  sessionId,
  active,
  onClose,
}: {
  sessionId: string;
  active: boolean;
  onClose: () => void;
}) {
  const [findings, setFindings] = useState<FindingRow[]>();
  const [query, setQuery] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const refreshAction = useRef(() => {});
  const closeButton = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    closeButton.current?.focus();
  }, []);
  useEffect(() => {
    if (!active) return;
    let disposed = false;
    let busy = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const refresh = async () => {
      if (disposed || busy || document.hidden) return;
      clearTimeout(timer);
      busy = true;
      setLoading(true);
      try {
        const data = await api.artifacts({ id: sessionId });
        if (!disposed) {
          setFindings(data.findings);
          setError("");
        }
      } catch (cause) {
        if (!disposed) setError(String(cause));
      } finally {
        busy = false;
        if (!disposed) {
          setLoading(false);
          if (!document.hidden) timer = setTimeout(() => void refresh(), 2000);
        }
      }
    };
    const visibility = () => {
      clearTimeout(timer);
      if (!document.hidden) void refresh();
    };
    refreshAction.current = () => void refresh();
    document.addEventListener("visibilitychange", visibility);
    void refresh();
    return () => {
      disposed = true;
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", visibility);
    };
  }, [sessionId, active]);
  const term = query.trim().toLowerCase();
  const matches = (findings ?? [])
    .filter((finding) =>
      [finding.title, finding.severity, finding.endpoint, finding.description]
        .join(" ")
        .toLowerCase()
        .includes(term),
    )
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
  return (
    <aside
      className="op-issues"
      aria-label="Issues"
      onKeyDown={(event) => {
        if (event.key === "Escape" && !event.defaultPrevented) {
          event.preventDefault();
          onClose();
        }
      }}
    >
      <div className="op-issues-header">
        <h2>Issues {findings && <span>{findings.length}</span>}</h2>
        <Button
          ref={closeButton}
          size="icon-xs"
          variant="ghost"
          aria-label="Close issues sidebar"
          onClick={onClose}
        >
          <X size={14} aria-hidden="true" />
        </Button>
      </div>
      <div className="op-issues-toolbar">
        <Input
          aria-label="Search issues"
          placeholder="Search issues…"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        <Button
          size="icon-sm"
          variant="ghost"
          aria-label="Refresh issues"
          disabled={loading}
          onClick={() => refreshAction.current()}
        >
          <RefreshCw size={14} aria-hidden="true" />
        </Button>
      </div>
      {error && (
        <p role="alert" className="op-issues-status">
          {error}
          {findings && " Showing the last loaded issues."}
        </p>
      )}
      <div className="op-issues-list">
        {!findings ? (
          <p className="op-issues-status">
            {error
              ? "Issues could not be loaded. Try refreshing."
              : "Loading issues…"}
          </p>
        ) : !matches.length ? (
          <p className="op-issues-status">
            {findings.length
              ? "No issues match your search."
              : "No issues found yet. Findings will appear here as they are documented."}
          </p>
        ) : (
          <Accordion type="multiple">
            {matches.map((finding) => {
              const key = JSON.stringify([finding.title, finding.endpoint]);
              return (
                <AccordionItem key={key} value={key} className="op-issue">
                  <AccordionTrigger className="op-issue-trigger">
                    <span className="op-issue-summary">
                      <Severity
                        level={finding.severity?.toLowerCase() || "unknown"}
                      />
                      <span className="op-issue-title">{finding.title}</span>
                      <span className="op-issue-endpoint">
                        {finding.endpoint}
                      </span>
                    </span>
                  </AccordionTrigger>
                  <AccordionContent className="op-issue-detail">
                    {(
                      [
                        ["Description", finding.description],
                        ["Impact", finding.impact],
                        ["Evidence", finding.evidence],
                        ["Remediation", finding.remediation],
                      ] as const
                    ).map(
                      ([label, value]) =>
                        value && (
                          <section key={label}>
                            <h3>{label}</h3>
                            <LocalMarkdown text={value} />
                          </section>
                        ),
                    )}
                  </AccordionContent>
                </AccordionItem>
              );
            })}
          </Accordion>
        )}
      </div>
    </aside>
  );
}
