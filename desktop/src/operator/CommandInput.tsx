import { Textarea } from "@pensarai/design-system/ui/textarea";
import { type ComponentProps, useLayoutEffect, useRef } from "react";
import type { OperatorSnapshot } from "./contract";
import { commandRange } from "./slash-commands";

type Props = Omit<ComponentProps<typeof Textarea>, "value"> & {
  value: string;
  skills: OperatorSnapshot["skills"];
};

export function CommandInput({
  value,
  skills,
  ref,
  onScroll,
  ...props
}: Props) {
  const input = useRef<HTMLTextAreaElement | null>(null);
  const highlight = useRef<HTMLDivElement | null>(null);
  const range = commandRange(value, skills);
  // biome-ignore lint/correctness/useExhaustiveDependencies: Text changes can scroll the caret without resizing the field.
  useLayoutEffect(() => {
    const field = input.current;
    const layer = highlight.current;
    if (!field || !layer) return;
    const sync = () => {
      layer.style.width = `${field.clientWidth}px`;
      layer.scrollTop = field.scrollTop;
      layer.scrollLeft = field.scrollLeft;
    };
    sync();
    const observer = new ResizeObserver(sync);
    observer.observe(field);
    return () => observer.disconnect();
  }, [value]);
  return (
    <div
      className={`op-command-input${range ? " op-command-highlighted" : ""}`}
    >
      <div ref={highlight} className="op-command-overlay" aria-hidden="true">
        {range && (
          <>
            {value.slice(0, range.start)}
            <span>{value.slice(range.start, range.end)}</span>
            {value.slice(range.end)}
            {"\n"}
          </>
        )}
      </div>
      <Textarea
        {...props}
        value={value}
        ref={(node) => {
          input.current = node;
          if (typeof ref === "function") return ref(node);
          if (ref) ref.current = node;
        }}
        onScroll={(event) => {
          if (highlight.current) {
            highlight.current.scrollTop = event.currentTarget.scrollTop;
            highlight.current.scrollLeft = event.currentTarget.scrollLeft;
          }
          onScroll?.(event);
        }}
      />
    </div>
  );
}
