import type { AgentRedTeamMutationId } from "../types";

export interface AgentRedTeamMutation {
  id: AgentRedTeamMutationId;
  name: string;
  category: "identity" | "encoding" | "unicode" | "format" | "concealment";
  encode(input: string): string;
  decode?: (input: string) => string;
  detect?: (input: string) => boolean;
}

function rot13(input: string): string {
  return input.replace(/[a-zA-Z]/g, (char) => {
    const base = char <= "Z" ? 65 : 97;
    return String.fromCharCode(((char.charCodeAt(0) - base + 13) % 26) + base);
  });
}

function htmlEntities(input: string): string {
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function decodeHtmlEntities(input: string): string {
  return input
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, "&");
}

const ZERO_WIDTH = "\u200b";
const TAG_BASE = 0xe0000;

function encodeUnicodeTags(input: string): string {
  return [...Buffer.from(input, "utf8")]
    .map((byte) => String.fromCodePoint(TAG_BASE + byte))
    .join("");
}

export function decodeUnicodeTags(input: string): string {
  const bytes: number[] = [];
  for (const char of input) {
    const codePoint = char.codePointAt(0);
    if (codePoint == null) continue;
    if (codePoint >= TAG_BASE && codePoint <= TAG_BASE + 0xff) {
      bytes.push(codePoint - TAG_BASE);
    }
  }
  if (bytes.length === 0) return "";
  return Buffer.from(bytes).toString("utf8");
}

const HOMOGLYPHS: Record<string, string> = {
  a: "а",
  e: "е",
  o: "о",
  p: "р",
  c: "с",
  x: "х",
  y: "у",
  A: "А",
  B: "В",
  E: "Е",
  K: "К",
  M: "М",
  H: "Н",
  O: "О",
  P: "Р",
  C: "С",
  T: "Т",
  X: "Х",
};

const REVERSE_HOMOGLYPHS = Object.fromEntries(
  Object.entries(HOMOGLYPHS).map(([plain, glyph]) => [glyph, plain]),
);

function mapChars(input: string, map: Record<string, string>): string {
  return [...input].map((char) => map[char] ?? char).join("");
}

export const AGENT_RED_TEAM_MUTATIONS: AgentRedTeamMutation[] = [
  {
    id: "identity",
    name: "Identity",
    category: "identity",
    encode: (input) => input,
  },
  {
    id: "base64",
    name: "Base64",
    category: "encoding",
    encode: (input) => Buffer.from(input, "utf8").toString("base64"),
    decode: (input) => Buffer.from(input, "base64").toString("utf8"),
    detect: (input) => /^[A-Za-z0-9+/=\s]{8,}$/.test(input.trim()),
  },
  {
    id: "hex",
    name: "Hex",
    category: "encoding",
    encode: (input) => Buffer.from(input, "utf8").toString("hex"),
    decode: (input) =>
      Buffer.from(input.replace(/\s+/g, ""), "hex").toString("utf8"),
    detect: (input) => /^(?:[0-9a-fA-F]{2}\s*){4,}$/.test(input.trim()),
  },
  {
    id: "rot13",
    name: "ROT13",
    category: "encoding",
    encode: rot13,
    decode: rot13,
    detect: (input) => /[A-Za-z]{8,}/.test(input),
  },
  {
    id: "url-encode",
    name: "URL Encode",
    category: "encoding",
    encode: encodeURIComponent,
    decode: decodeURIComponent,
    detect: (input) => /%[0-9A-Fa-f]{2}/.test(input),
  },
  {
    id: "html-entities",
    name: "HTML Entities",
    category: "encoding",
    encode: htmlEntities,
    decode: decodeHtmlEntities,
    detect: (input) => /&(amp|lt|gt|quot|#39);/.test(input),
  },
  {
    id: "random-case",
    name: "Deterministic Mixed Case",
    category: "format",
    encode: (input) =>
      [...input]
        .map((char, index) =>
          index % 2 === 0 ? char.toUpperCase() : char.toLowerCase(),
        )
        .join(""),
  },
  {
    id: "zero-width-between-chars",
    name: "Zero Width Between Characters",
    category: "unicode",
    encode: (input) => [...input].join(ZERO_WIDTH),
    decode: (input) => input.replaceAll(ZERO_WIDTH, ""),
    detect: (input) => input.includes(ZERO_WIDTH),
  },
  {
    id: "unicode-tags",
    name: "Unicode Tags",
    category: "concealment",
    encode: encodeUnicodeTags,
    decode: decodeUnicodeTags,
    detect: (input) =>
      [...input].some((char) => {
        const codePoint = char.codePointAt(0);
        return (
          codePoint != null &&
          codePoint >= TAG_BASE &&
          codePoint <= TAG_BASE + 0xff
        );
      }),
  },
  {
    id: "homoglyph-lite",
    name: "Homoglyph Lite",
    category: "unicode",
    encode: (input) => mapChars(input, HOMOGLYPHS),
    decode: (input) => mapChars(input, REVERSE_HOMOGLYPHS),
    detect: (input) =>
      [...input].some((char) => Object.hasOwn(REVERSE_HOMOGLYPHS, char)),
  },
  {
    id: "markdown-comment",
    name: "Markdown HTML Comment",
    category: "concealment",
    encode: (input) => `Visible benign note.\n<!-- ${input} -->`,
    decode: (input) =>
      [...input.matchAll(/<!--([\s\S]*?)-->/g)]
        .map((match) => match[1]?.trim() ?? "")
        .filter(Boolean)
        .join("\n"),
    detect: (input) => /<!--[\s\S]*?-->/.test(input),
  },
  {
    id: "html-hidden",
    name: "Hidden HTML Element",
    category: "concealment",
    encode: (input) =>
      `<div>Visible benign content.</div><span style="display:none">${htmlEntities(input)}</span>`,
    decode: (input) =>
      [
        ...input.matchAll(
          /<span[^>]*display\s*:\s*none[^>]*>([\s\S]*?)<\/span>/gi,
        ),
      ]
        .map((match) => decodeHtmlEntities(match[1]?.trim() ?? ""))
        .filter(Boolean)
        .join("\n"),
    detect: (input) => /display\s*:\s*none/i.test(input),
  },
];

export class AgentRedTeamMutationRegistry {
  private readonly mutations = new Map(
    AGENT_RED_TEAM_MUTATIONS.map((mutation) => [mutation.id, mutation]),
  );

  list(): AgentRedTeamMutation[] {
    return [...this.mutations.values()];
  }

  get(id: AgentRedTeamMutationId): AgentRedTeamMutation {
    const mutation = this.mutations.get(id);
    if (!mutation) throw new Error(`Unknown agent red-team mutation: ${id}`);
    return mutation;
  }

  apply(input: string, chain: AgentRedTeamMutationId[]): string {
    return chain.reduce((value, id) => this.get(id).encode(value), input);
  }
}
