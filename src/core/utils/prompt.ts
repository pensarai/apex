/**
 * Core utility for threat model content wrapping.
 *
 * Provides the preamble template used by both the CLI (via resolveThreatModelPrompt)
 * and the programmatic API (via runPentestWorkflow). Does NOT handle @file resolution —
 * that is the caller's responsibility.
 */

/**
 * Wrap raw threat model content with the standard preamble that instructs
 * the pentest agent on how to use the threat model.
 */
export function createThreatModelPrompt(content: string): string {
  return `## Threat Model

The following threat model was generated for this application. Use it to guide your pentest:

1. **Prioritize attack paths by severity** — start with Critical and High severity paths.
2. **Use the pentest guidance** — each attack path includes specific objectives, techniques, and example payloads. Follow these when testing.
3. **Check existing controls** — the threat model documents existing security controls. Verify they work as documented and look for bypasses.
4. **Verify control gaps** — each attack path lists control gaps. These are your highest-value targets.
5. **Reference attacker profiles** — understand who would attack this application and what they control. This shapes your testing perspective.
6. **Don't limit yourself** — the threat model is guidance, not an exhaustive list. If you discover attack vectors not covered by the model, pursue them.

<threat-model>
${content}
</threat-model>`;
}
