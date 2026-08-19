import { AgentRedTeamMutationRegistry } from "./registry";

export interface DecodedView {
  kind: "raw" | "normalized" | "decoded" | "visible" | "hidden";
  label: string;
  content: string;
}

const TAG_CHARS = /[\u{e0000}-\u{e00ff}]/gu;

function isInvisibleCodePoint(codePoint: number): boolean {
  return (
    (codePoint >= 0x200b && codePoint <= 0x200f) ||
    (codePoint >= 0x202a && codePoint <= 0x202e) ||
    (codePoint >= 0x2060 && codePoint <= 0x206f) ||
    (codePoint >= 0xfe00 && codePoint <= 0xfe0f)
  );
}

function stripInvisible(input: string): string {
  return [...input]
    .filter((char) => {
      const codePoint = char.codePointAt(0);
      return codePoint == null || !isInvisibleCodePoint(codePoint);
    })
    .join("");
}

export function normalizedView(input: string): string {
  return stripInvisible(input.normalize("NFKC"));
}

export function visibleTextView(input: string): string {
  return normalizedView(input)
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<[^>]*display\s*:\s*none[^>]*>[\s\S]*?<\/[^>]+>/gi, "")
    .replace(TAG_CHARS, "");
}

export function hiddenTextView(input: string): string {
  const hidden: string[] = [];
  for (const match of input.matchAll(/<!--([\s\S]*?)-->/g)) {
    if (match[1]?.trim()) hidden.push(match[1].trim());
  }
  for (const match of input.matchAll(
    /<[^>]*display\s*:\s*none[^>]*>([\s\S]*?)<\/[^>]+>/gi,
  )) {
    if (match[1]?.trim()) hidden.push(match[1].trim());
  }
  const tags = [...input.matchAll(TAG_CHARS)].map((match) => match[0]).join("");
  if (tags) hidden.push(tags);
  return hidden.join("\n");
}

export function decodeViews(
  input: string,
  registry = new AgentRedTeamMutationRegistry(),
): DecodedView[] {
  const views: DecodedView[] = [
    { kind: "raw", label: "raw", content: input },
    {
      kind: "normalized",
      label: "NFKC normalized",
      content: normalizedView(input),
    },
    { kind: "visible", label: "visible text", content: visibleTextView(input) },
  ];

  const hidden = hiddenTextView(input);
  if (hidden) {
    views.push({ kind: "hidden", label: "hidden text", content: hidden });
  }

  const seen = new Set(views.map((view) => `${view.kind}:${view.content}`));
  for (const mutation of registry.list()) {
    if (!mutation.decode || !mutation.detect?.(input)) continue;
    try {
      const decoded = mutation.decode(input);
      if (!decoded || decoded === input) continue;
      const key = `decoded:${decoded}`;
      if (seen.has(key)) continue;
      seen.add(key);
      views.push({
        kind: "decoded",
        label: `decoded via ${mutation.name}`,
        content: decoded,
      });
    } catch {
      // Decoder failures are expected for broad detectors.
    }
  }

  if (hidden) {
    for (const mutation of registry.list()) {
      if (!mutation.decode || !mutation.detect?.(hidden)) continue;
      try {
        const decoded = mutation.decode(hidden);
        if (!decoded || decoded === hidden) continue;
        const key = `decoded:${decoded}`;
        if (seen.has(key)) continue;
        seen.add(key);
        views.push({
          kind: "decoded",
          label: `decoded hidden text via ${mutation.name}`,
          content: decoded,
        });
      } catch {
        // Decoder failures are expected for broad detectors.
      }
    }
  }

  return views;
}
