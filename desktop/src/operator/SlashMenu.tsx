import { Button } from "@pensarai/design-system/ui/button";
import { Target, Terminal, Zap } from "lucide-react";
import { useEffect, useRef } from "react";
import type { SlashEntry } from "./slash-commands";

export function SlashMenu({
  id,
  entries,
  selected,
  onSelect,
}: {
  id: string;
  entries: SlashEntry[];
  selected?: string;
  onSelect: (slug: string) => void;
}) {
  const current = useRef<HTMLButtonElement>(null);
  // biome-ignore lint/correctness/useExhaustiveDependencies: The selected option must stay visible as the composer navigates the list.
  useEffect(() => {
    current.current?.scrollIntoView({ block: "nearest" });
  }, [selected]);
  return (
    <div className="op-slash-menu">
      <div
        id={id}
        role="listbox"
        aria-label="Commands and skills"
        className="op-slash-list"
      >
        {!entries.length && (
          <p className="op-slash-empty">No matching commands or skills.</p>
        )}
        {entries.map((entry) => {
          const Icon =
            entry.slug === "goal"
              ? Target
              : entry.kind === "skill"
                ? Zap
                : Terminal;
          return (
            <Button
              key={entry.slug}
              ref={entry.slug === selected ? current : undefined}
              id={`${id}-${entry.slug}`}
              role="option"
              aria-selected={entry.slug === selected}
              tabIndex={-1}
              variant="ghost"
              className="op-slash-item"
              onMouseDown={(event) => event.preventDefault()}
              onClick={() => onSelect(entry.slug)}
            >
              <Icon size={15} aria-hidden="true" />
              <span className="op-slash-description">
                <strong>/{entry.slug}</strong>
                <span>{entry.description}</span>
              </span>
              <span className="op-slash-kind">{entry.kind}</span>
            </Button>
          );
        })}
      </div>
      <div className="op-slash-hint">
        ↑ ↓ Navigate · Tab / Enter Insert · Esc Dismiss
      </div>
    </div>
  );
}
