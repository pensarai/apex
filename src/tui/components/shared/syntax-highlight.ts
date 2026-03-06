/**
 * Syntax Highlighting for Terminal UI
 *
 * Tokenizes code via highlight.js and maps the output to StyledText
 * chunks with per-token foreground colors for rich terminal rendering.
 */

import { RGBA, StyledText, type TextChunk } from "@opentui/core";
import hljs from "highlight.js";
import { extname } from "path";

// ---------------------------------------------------------------------------
// Color palette — dark-theme-friendly terminal colors
// ---------------------------------------------------------------------------

const C = {
  keyword: RGBA.fromInts(198, 120, 221, 255), // purple
  string: RGBA.fromInts(152, 195, 121, 255), // green
  comment: RGBA.fromInts(106, 115, 125, 255), // gray
  number: RGBA.fromInts(209, 154, 102, 255), // orange
  function: RGBA.fromInts(97, 175, 239, 255), // blue
  title: RGBA.fromInts(97, 175, 239, 255), // blue
  attr: RGBA.fromInts(229, 192, 123, 255), // yellow
  tag: RGBA.fromInts(224, 108, 117, 255), // red
  type: RGBA.fromInts(86, 182, 194, 255), // cyan
  literal: RGBA.fromInts(209, 154, 102, 255), // orange
  regexp: RGBA.fromInts(152, 195, 121, 255), // green
  meta: RGBA.fromInts(106, 115, 125, 255), // gray
  punctuation: RGBA.fromInts(171, 178, 191, 255), // light gray
} as const;

const CLASS_COLOR_MAP: Record<string, RGBA> = {
  "hljs-keyword": C.keyword,
  "hljs-built_in": C.keyword,
  "hljs-type": C.type,
  "hljs-literal": C.literal,
  "hljs-number": C.number,
  "hljs-string": C.string,
  "hljs-regexp": C.regexp,
  "hljs-template-variable": C.string,
  "hljs-subst": C.string,
  "hljs-comment": C.comment,
  "hljs-doctag": C.comment,
  "hljs-function": C.function,
  "hljs-title": C.title,
  "hljs-title.class_": C.type,
  "hljs-title.function_": C.function,
  "hljs-params": C.attr,
  "hljs-attr": C.attr,
  "hljs-attribute": C.attr,
  "hljs-property": C.attr,
  "hljs-variable": C.tag,
  "hljs-tag": C.tag,
  "hljs-name": C.tag,
  "hljs-selector-tag": C.tag,
  "hljs-selector-class": C.attr,
  "hljs-selector-id": C.attr,
  "hljs-meta": C.meta,
  "hljs-meta keyword": C.keyword,
  "hljs-symbol": C.literal,
  "hljs-punctuation": C.punctuation,
};

// ---------------------------------------------------------------------------
// Extension → highlight.js language mapping
// ---------------------------------------------------------------------------

const EXT_LANG_MAP: Record<string, string> = {
  ".ts": "typescript",
  ".tsx": "typescript",
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".py": "python",
  ".rb": "ruby",
  ".rs": "rust",
  ".go": "go",
  ".java": "java",
  ".kt": "kotlin",
  ".kts": "kotlin",
  ".swift": "swift",
  ".c": "c",
  ".h": "c",
  ".cpp": "cpp",
  ".cc": "cpp",
  ".hpp": "cpp",
  ".cs": "csharp",
  ".php": "php",
  ".sh": "bash",
  ".bash": "bash",
  ".zsh": "bash",
  ".fish": "bash",
  ".sql": "sql",
  ".html": "xml",
  ".htm": "xml",
  ".xml": "xml",
  ".svg": "xml",
  ".css": "css",
  ".scss": "scss",
  ".less": "less",
  ".json": "json",
  ".yaml": "yaml",
  ".yml": "yaml",
  ".toml": "ini",
  ".ini": "ini",
  ".md": "markdown",
  ".lua": "lua",
  ".r": "r",
  ".R": "r",
  ".pl": "perl",
  ".ex": "elixir",
  ".exs": "elixir",
  ".erl": "erlang",
  ".hs": "haskell",
  ".scala": "scala",
  ".dart": "dart",
  ".dockerfile": "dockerfile",
  ".tf": "hcl",
  ".vue": "xml",
  ".graphql": "graphql",
  ".gql": "graphql",
  ".proto": "protobuf",
  ".nginx": "nginx",
  ".conf": "nginx",
};

function inferLanguage(filePath: string): string | undefined {
  const ext = extname(filePath).toLowerCase();
  if (EXT_LANG_MAP[ext]) return EXT_LANG_MAP[ext];
  const base = filePath.split("/").pop()?.toLowerCase() ?? "";
  if (base === "dockerfile" || base.startsWith("dockerfile."))
    return "dockerfile";
  if (base === "makefile" || base === "gnumakefile") return "makefile";
  return undefined;
}

// ---------------------------------------------------------------------------
// HTML → TextChunk[] parser
// ---------------------------------------------------------------------------

const ENTITY_MAP: Record<string, string> = {
  "&amp;": "&",
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&#x27;": "'",
  "&#39;": "'",
};
const ENTITY_RE = /&(?:amp|lt|gt|quot|#x27|#39);/g;

function decodeEntities(s: string): string {
  return s.replace(ENTITY_RE, (m) => ENTITY_MAP[m] ?? m);
}

/**
 * Parse highlight.js HTML output into TextChunk[].
 *
 * The HTML is simple: flat or shallowly nested `<span class="hljs-*">` tags.
 * We track a color stack so nested spans inherit/override correctly.
 */
function parseHljsHtml(html: string): TextChunk[] {
  const chunks: TextChunk[] = [];
  const colorStack: (RGBA | undefined)[] = [undefined];

  const TAG_RE = /<span\s+class="([^"]*)"[^>]*>|<\/span>|([^<]+)|(<[^>]*>)/g;
  let m: RegExpExecArray | null;

  while ((m = TAG_RE.exec(html)) !== null) {
    if (m[1] !== undefined) {
      // Opening <span class="...">
      const classes = m[1].split(/\s+/);
      let color: RGBA | undefined;
      for (const cls of classes) {
        if (CLASS_COLOR_MAP[cls]) {
          color = CLASS_COLOR_MAP[cls];
          break;
        }
      }
      // Also try combined class (e.g. "hljs-title function_")
      if (!color && classes.length > 1) {
        color = CLASS_COLOR_MAP[classes.join(" ")];
      }
      colorStack.push(color ?? colorStack[colorStack.length - 1]);
    } else if (m[0] === "</span>") {
      if (colorStack.length > 1) colorStack.pop();
    } else if (m[2] !== undefined) {
      // Text node
      const text = decodeEntities(m[2]);
      if (text) {
        chunks.push({
          __isChunk: true,
          text,
          fg: colorStack[colorStack.length - 1],
          attributes: 0,
        });
      }
    }
    // Ignore other tags
  }

  return chunks;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Syntax-highlight code and return a StyledText for terminal rendering.
 *
 * @param code - Source code to highlight
 * @param filePath - Optional file path to infer language from extension
 * @returns StyledText with per-token colors, or null if highlighting fails
 */
export function highlightCode(
  code: string,
  filePath?: string,
): StyledText | null {
  if (!code.trim()) return null;

  try {
    const lang = filePath ? inferLanguage(filePath) : undefined;

    const result =
      lang && hljs.getLanguage(lang)
        ? hljs.highlight(code, { language: lang, ignoreIllegals: true })
        : hljs.highlightAuto(code);

    if (!result.value) return null;

    const chunks = parseHljsHtml(result.value);
    if (chunks.length === 0) return null;

    return new StyledText(chunks);
  } catch {
    return null;
  }
}
