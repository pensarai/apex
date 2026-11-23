import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@pensarai/design-system/ui/collapsible";
import { ChevronRight } from "lucide-react";
import { ThinkingOrb } from "thinking-orbs";
import type { DisplayReasoning } from "../../../src/core/session/persistence";

export function ReasoningMessage({
  reasoning,
}: {
  reasoning: DisplayReasoning;
}) {
  const { text, startedAt, endedAt, complete } = reasoning;
  const body = text.replace(/\[REDACTED\]/g, "").trim();
  if (complete && !body) return null;
  const seconds =
    startedAt != null && endedAt != null
      ? Math.max(1, Math.round((endedAt - startedAt) / 1000))
      : undefined;
  const label = !complete
    ? "Thinking…"
    : seconds != null
      ? `Thought for ${seconds}s`
      : "Thought process";
  return (
    <Collapsible className="op-reasoning">
      <CollapsibleTrigger className="op-activity op-reasoning-trigger">
        <ThinkingOrb
          state="solving"
          size={20}
          theme="auto"
          paused={complete}
          aria-hidden="true"
        />
        <span>{label}</span>
        <ChevronRight
          size={12}
          className="op-reasoning-chevron"
          aria-hidden="true"
        />
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div className="op-reasoning-body">{body}</div>
      </CollapsibleContent>
    </Collapsible>
  );
}
