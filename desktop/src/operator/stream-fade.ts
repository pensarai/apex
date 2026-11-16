export const streamFadeDuration = 160;

export type Arrival = { start: number; end: number; time: number };
export type StreamArrival = { text: string; arrivals: Arrival[] };

export function advanceStream(
  previous: StreamArrival,
  text: string,
  now: number,
  animate: boolean,
): StreamArrival {
  if (!animate || !text.startsWith(previous.text))
    return { text, arrivals: [] };
  const arrivals = previous.arrivals.filter(
    (arrival) => now - arrival.time < streamFadeDuration,
  );
  if (text.length > previous.text.length)
    arrivals.push({ start: previous.text.length, end: text.length, time: now });
  return { text, arrivals };
}

type Node = {
  type: string;
  tagName?: string;
  value?: string;
  children?: Node[];
  properties?: Record<string, unknown>;
  position?: { start: { offset?: number }; end: { offset?: number } };
};

export function streamFadePlugin(arrivals: Arrival[], now: number) {
  return () => (tree: Node) => {
    const visit = (parent: Node) => {
      // Code children must stay strings for the design system's syntax renderer.
      if (!parent.children || parent.tagName === "code") return;
      parent.children = parent.children.flatMap((node) => {
        if (node.type !== "text" || !node.value || !node.position) {
          visit(node);
          return [node];
        }
        const start = node.position.start.offset;
        const end = node.position.end.offset;
        if (start === undefined || end === undefined) return [node];
        // Preserve decoded entities and escapes without replaying the surrounding text.
        if (end - start !== node.value.length) return [node];
        const active = arrivals.filter((a) => a.end > start && a.start < end);
        if (!active.length) return [node];
        const parts: Node[] = [];
        let cursor = 0;
        for (const arrival of active) {
          const from = Math.max(cursor, arrival.start - start);
          const to = Math.min(node.value.length, arrival.end - start);
          if (from > cursor)
            parts.push({ type: "text", value: node.value.slice(cursor, from) });
          parts.push({
            type: "element",
            tagName: "span",
            properties: {
              className: ["op-stream-arrival"],
              style: `animation-delay: -${Math.max(0, now - arrival.time)}ms`,
            },
            children: [{ type: "text", value: node.value.slice(from, to) }],
          });
          cursor = to;
        }
        if (cursor < node.value.length)
          parts.push({ type: "text", value: node.value.slice(cursor) });
        return parts;
      });
    };
    visit(tree);
  };
}
