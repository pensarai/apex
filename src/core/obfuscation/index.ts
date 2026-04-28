/**
 * Obfuscation Engine
 *
 * Detects and redacts sensitive content (PII, company names, identifiers,
 * URLs, IPs, hostnames, file paths, emails, credentials, UUIDs, tokens, etc.)
 * for screenshot-safe display in the TUI when `--obfuscate` is active.
 *
 * Design goals:
 *  - **Stable mapping**: the same input value always produces the same
 *    placeholder within a process lifetime, so redacted output stays
 *    legible (the same email becomes `<EMAIL_1>` everywhere).
 *  - **Pattern-based**: no LLM call is required — every detection is a
 *    regex over the text. This keeps redaction synchronous, deterministic
 *    and cheap enough to run on every render.
 *  - **Allowlist**: well-known public hostnames and reserved/example
 *    domains are not redacted, since they don't leak engagement detail.
 */

export {
  obfuscate,
  obfuscateValue,
  deobfuscate,
  resetObfuscation,
  isObfuscationEnabled,
  setObfuscationEnabled,
} from "./engine";
export type { ObfuscationCategory } from "./engine";
