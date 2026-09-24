// Glob→RegExp translator shared by every glob backend (local and sandbox) so
// matching semantics are identical wherever the files live. Supports the
// documented forms: ** as a full path segment, *, ?, [...], and {a,b}
// alternation. dot:false semantics — wildcards never match a segment's
// leading ".". Anything else (absolute patterns, ".." segments, mid-segment
// "**") is rejected with a clear error rather than silently reinterpreted.

const MAX_BRACE_VARIANTS = 64;

export type GlobPattern = { regexes: RegExp[] } | { error: string };

function expandBraces(pattern: string): string[] | { error: string } {
  const open = pattern.indexOf("{");
  if (open === -1) return [pattern];
  // Find the matching close for the FIRST group; nested groups expand
  // recursively via subsequent passes.
  let depth = 0;
  let close = -1;
  for (let i = open; i < pattern.length; i++) {
    if (pattern[i] === "{") depth++;
    else if (pattern[i] === "}") {
      depth--;
      if (depth === 0) {
        close = i;
        break;
      }
    }
  }
  if (close === -1) {
    return { error: `unbalanced { in glob pattern: ${pattern}` };
  }
  const prefix = pattern.slice(0, open);
  const body = pattern.slice(open + 1, close);
  const suffix = pattern.slice(close + 1);
  // Split alternatives on commas that are not inside a nested group.
  const alts: string[] = [];
  let part = "";
  let nested = 0;
  for (const ch of body) {
    if (ch === "{") nested++;
    if (ch === "}") nested--;
    if (ch === "," && nested === 0) {
      alts.push(part);
      part = "";
    } else {
      part += ch;
    }
  }
  alts.push(part);
  const variants: string[] = [];
  for (const alt of alts) {
    const sub = expandBraces(`${prefix}${alt}${suffix}`);
    if ("error" in sub) return sub;
    variants.push(...sub);
    if (variants.length > MAX_BRACE_VARIANTS) {
      return {
        error: `glob pattern expands to too many alternatives (over ${MAX_BRACE_VARIANTS}): ${pattern}`,
      };
    }
  }
  return variants;
}

function escapeLiteral(ch: string): string {
  return /[\\^$.|+(){}[\]]/.test(ch) ? `\\${ch}` : ch;
}

function classToRegex(body: string): string | { error: string } {
  // [...] body without brackets; support leading ! or ^ negation and \-escapes.
  let negated = false;
  let rest = body;
  if (rest.startsWith("!") || rest.startsWith("^")) {
    negated = true;
    rest = rest.slice(1);
  }
  let out = "";
  for (let i = 0; i < rest.length; i++) {
    const ch = rest[i];
    if (ch === "\\" && i + 1 < rest.length) {
      out += escapeLiteral(rest[++i]);
      continue;
    }
    // Ranges keep their meaning; regex metachars are literal inside a class.
    out += /[\\\]^]/.test(ch) ? `\\${ch}` : ch;
  }
  return negated ? `[^${out}]` : `[${out}]`;
}

function segmentToRegex(segment: string): string | { error: string } {
  if (segment === "**") return "**";
  if (segment.includes("**")) {
    return {
      error: `** is only supported as a full path segment, not inside "${segment}"`,
    };
  }
  // dot:false — a wildcard opening the segment never matches a leading ".".
  const startsWithWildcard = /^[*?[]/.test(segment);
  let out = "";
  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i];
    if (ch === "*") {
      out += "[^/]*";
      continue;
    }
    if (ch === "?") {
      out += "[^/]";
      continue;
    }
    if (ch === "[") {
      const close = segment.indexOf("]", i + 1);
      if (close === -1) return { error: "unterminated [ in glob pattern" };
      const cls = classToRegex(segment.slice(i + 1, close));
      if (typeof cls !== "string") return cls;
      out += `(?!/)${cls}`;
      i = close;
      continue;
    }
    if (ch === "{" || ch === "}") {
      // Unreachable after brace expansion — leftover braces are unbalanced.
      return { error: `unbalanced { in glob pattern: ${segment}` };
    }
    out += escapeLiteral(ch);
  }
  return startsWithWildcard ? `(?!\\.)${out}` : out;
}

function variantToRegex(variant: string): RegExp | { error: string } {
  const normalized = variant.replace(/\\/g, "/");
  if (normalized.startsWith("/") || /^[A-Za-z]:/.test(normalized)) {
    return {
      error:
        "glob pattern must be relative to the search root — absolute patterns are not supported",
    };
  }
  const segments = normalized.split("/");
  if (segments.some((seg) => seg === "..")) {
    return {
      error:
        "glob patterns cannot contain '..' segments — search a narrower root instead",
    };
  }
  let out = "^";
  let separatorPending = false;
  for (let i = 0; i < segments.length; i++) {
    const seg = segmentToRegex(segments[i]);
    if (typeof seg !== "string") return seg;
    if (seg === "**") {
      if (i === 0 && i === segments.length - 1) {
        // ** alone: any path whose segments never start with a dot.
        out += "(?:(?!\\.)[^/]+(?:/(?!\\.)[^/]+)*)?";
      } else if (i === 0) {
        // Leading **/ consumes its trailing separator itself; every matched
        // segment is dot-guarded.
        out += "(?:(?!\\.)[^/]+/)*";
        separatorPending = false;
      } else if (i === segments.length - 1) {
        // Trailing /**: zero or more dot-guarded deeper segments.
        out += "(?:/(?!\\.)[^/]+)*";
      } else {
        // Interior **: the following segment still emits its own separator.
        out += "(?:/(?!\\.)[^/]+)*";
      }
      continue;
    }
    if (i > 0 && separatorPending) out += "/";
    separatorPending = true;
    out += seg;
  }
  return new RegExp(`${out}$`);
}

export function compileGlobPattern(pattern: string): GlobPattern {
  if (!pattern || pattern.includes("\0")) {
    return { error: "glob pattern must be nonempty and contain no NUL bytes" };
  }
  const variants = expandBraces(pattern);
  if ("error" in variants) return variants;
  const regexes: RegExp[] = [];
  for (const variant of variants) {
    const regex = variantToRegex(variant);
    if ("error" in regex) return regex;
    regexes.push(regex);
  }
  return { regexes };
}
