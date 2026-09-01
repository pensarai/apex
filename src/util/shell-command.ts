/**
 * Shell command display helpers.
 *
 * Agents frequently prefix commands with environment setup so that tools
 * installed outside the default distro PATH resolve, e.g.
 *
 *   export PATH="/opt/tools/bin:$PATH" && nmap -sV target
 *   FOO=bar BAR=baz ./scanner --target host
 *
 * When such a command is summarized for an operator approval prompt the
 * leading `export …`/`VAR=…` noise can push the meaningful command past the
 * truncation window, leaving the operator approving a command they cannot
 * see. {@link stripEnvAssignmentPrefix} drops those leading assignments so the
 * actual command surfaces. It is display-only and never used to rewrite a
 * command that is executed.
 */

// One leading assignment, optionally `export`-prefixed, optionally followed by
// a command separator (`&&`, `;`, `||`). The value is a quoted string or a run
// of non-whitespace characters (covers `$VAR`, `:`, paths, etc.).
const LEADING_ASSIGNMENT =
  /^(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|\S+)\s*(?:(?:&&|\|\||;)\s*)?/;

/**
 * Strip leading environment-variable assignments / `export` statements from a
 * shell command, returning the first meaningful command. Falls back to the
 * original (trimmed) command if stripping would leave nothing behind.
 */
export function stripEnvAssignmentPrefix(command: string): string {
  let rest = command.trim();

  for (;;) {
    const stripped = rest.replace(LEADING_ASSIGNMENT, "");
    if (stripped === rest) break;
    rest = stripped;
  }

  return rest.length > 0 ? rest : command.trim();
}
