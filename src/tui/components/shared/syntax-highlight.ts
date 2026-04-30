/**
 * Syntax Highlighting for Terminal UI
 *
 * Tokenizes code via highlight.js and maps the output to StyledText
 * chunks with per-token foreground colors for rich terminal rendering.
 *
 * Colors are theme-aware: each theme defines its own syntax palette
 * with dark/light variants via ThemeColors tokens.
 */

import { RGBA, StyledText, type TextChunk } from "@opentui/core";
import hljs from "highlight.js";
import { extname } from "path";
import type { ThemeColors } from "../../theme/types";

// ---------------------------------------------------------------------------
// Build hljs class → RGBA map from resolved theme colors
// ---------------------------------------------------------------------------

function buildClassColorMap(colors: ThemeColors): Record<string, RGBA> {
  return {
    "hljs-keyword": colors.syntaxKeyword,
    "hljs-built_in": colors.syntaxKeyword,
    "hljs-type": colors.syntaxType,
    "hljs-literal": colors.syntaxNumber,
    "hljs-number": colors.syntaxNumber,
    "hljs-string": colors.syntaxString,
    "hljs-regexp": colors.syntaxString,
    "hljs-template-variable": colors.syntaxString,
    "hljs-subst": colors.syntaxString,
    "hljs-comment": colors.syntaxComment,
    "hljs-doctag": colors.syntaxComment,
    "hljs-function": colors.syntaxFunction,
    "hljs-title": colors.syntaxFunction,
    "hljs-title.class_": colors.syntaxType,
    "hljs-title.function_": colors.syntaxFunction,
    "hljs-params": colors.syntaxAttr,
    "hljs-attr": colors.syntaxAttr,
    "hljs-attribute": colors.syntaxAttr,
    "hljs-property": colors.syntaxAttr,
    "hljs-variable": colors.syntaxTag,
    "hljs-tag": colors.syntaxTag,
    "hljs-name": colors.syntaxTag,
    "hljs-selector-tag": colors.syntaxTag,
    "hljs-selector-class": colors.syntaxAttr,
    "hljs-selector-id": colors.syntaxAttr,
    "hljs-meta": colors.syntaxComment,
    "hljs-meta keyword": colors.syntaxKeyword,
    "hljs-symbol": colors.syntaxNumber,
    "hljs-punctuation": colors.syntaxPunctuation,
  };
}

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
 *
 * `defaultColor` is used for any text outside an hljs span (whitespace,
 * punctuation like `{`, `}`, `|`, `;`, plain identifiers). Chunks with no
 * explicit `fg` fall back to opentui's white default rather than the parent
 * `<text fg=…>`, so unclassed tokens render as invisible white in light
 * themes unless we set this explicitly.
 */
function parseHljsHtml(
  html: string,
  classColorMap: Record<string, RGBA>,
  defaultColor: RGBA,
): TextChunk[] {
  const chunks: TextChunk[] = [];
  const colorStack: RGBA[] = [defaultColor];

  const TAG_RE = /<span\s+class="([^"]*)"[^>]*>|<\/span>|([^<]+)|(<[^>]*>)/g;
  let m: RegExpExecArray | null;

  while ((m = TAG_RE.exec(html)) !== null) {
    if (m[1] !== undefined) {
      // Opening <span class="...">
      const classes = m[1].split(/\s+/);
      let color: RGBA | undefined;
      for (const cls of classes) {
        if (classColorMap[cls]) {
          color = classColorMap[cls];
          break;
        }
      }
      // Also try combined class (e.g. "hljs-title function_")
      if (!color && classes.length > 1) {
        color = classColorMap[classes.join(" ")];
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
 * @param colors - Resolved ThemeColors for the current theme + mode
 * @returns StyledText with per-token colors, or null if highlighting fails
 */
export function highlightCode(
  code: string,
  filePath?: string,
  colors?: ThemeColors,
): StyledText | null {
  if (!code.trim()) return null;
  if (!colors) return null;

  try {
    const lang = filePath ? inferLanguage(filePath) : undefined;

    const result =
      lang && hljs.getLanguage(lang)
        ? hljs.highlight(code, { language: lang, ignoreIllegals: true })
        : hljs.highlightAuto(code);

    if (!result.value) return null;

    const classColorMap = buildClassColorMap(colors);
    const chunks = parseHljsHtml(result.value, classColorMap, colors.text);
    if (chunks.length === 0) return null;

    return new StyledText(chunks);
  } catch {
    return null;
  }
}
