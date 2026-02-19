/**
 * Credentials Panel - Shows discovered credentials with source/scope
 * Display only in Tier 1 (keyboard actions deferred to Tier 2)
 */

import type { Credential } from "../types";
import { useTheme } from "../../../theme";

interface CredentialsPanelProps {
  credentials: Credential[];
  maxVisible?: number;
}

export function CredentialsPanel({
  credentials,
  maxVisible = 4,
}: CredentialsPanelProps) {
  const { colors } = useTheme();
  const visible = credentials.slice(0, maxVisible);
  const remaining = credentials.length - maxVisible;

  return (
    <box flexDirection="column" gap={1}>
      <text fg={colors.text}>
        Credentials{" "}
        {credentials.length > 0 && (
          <span fg={colors.textMuted}>({credentials.length})</span>
        )}
      </text>

      {credentials.length === 0 ? (
        <text fg={colors.textMuted}>None discovered</text>
      ) : (
        <>
          {visible.map((cred) => (
            <box key={cred.id} flexDirection="column">
              <box flexDirection="row" gap={1}>
                {/* Active indicator */}
                <text fg={cred.isActive ? colors.warning : colors.textMuted}>
                  {cred.isActive ? "★" : " "}
                </text>
                {/* Username:redacted */}
                <text fg={cred.isActive ? colors.primary : colors.textMuted}>
                  {cred.username}:{redactSecret(cred.secret)}
                </text>
                {/* Scope */}
                <text fg={colors.accent}>({cred.scope})</text>
              </box>
              {/* Source on next line if active */}
              {cred.isActive && cred.source && (
                <text fg={colors.textMuted}>
                  {" "}
                  from: {truncate(cred.source, 18)}
                </text>
              )}
            </box>
          ))}
          {remaining > 0 && (
            <text fg={colors.textMuted}>... +{remaining} more</text>
          )}
        </>
      )}
    </box>
  );
}

/**
 * Redact secret for display (show first char, then ****)
 */
function redactSecret(secret: string): string {
  if (!secret || secret.length === 0) return "****";
  if (secret.length <= 2) return "****";
  return "****"; // Full redaction for security
}

function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + "...";
}
