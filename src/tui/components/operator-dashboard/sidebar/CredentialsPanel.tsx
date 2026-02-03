/**
 * Credentials Panel - Shows discovered credentials with source/scope
 * Display only in Tier 1 (keyboard actions deferred to Tier 2)
 */

import { RGBA } from "@opentui/core";
import type { Credential } from "../types";

const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);
const greenAccent = RGBA.fromInts(76, 175, 80, 255);
const yellowText = RGBA.fromInts(255, 235, 59, 255);
const blueText = RGBA.fromInts(100, 181, 246, 255);

interface CredentialsPanelProps {
  credentials: Credential[];
  maxVisible?: number;
}

export function CredentialsPanel({ credentials, maxVisible = 4 }: CredentialsPanelProps) {
  const visible = credentials.slice(0, maxVisible);
  const remaining = credentials.length - maxVisible;

  return (
    <box flexDirection="column" gap={1}>
      <text fg={creamText}>
        Credentials {credentials.length > 0 && <span fg={dimText}>({credentials.length})</span>}
      </text>

      {credentials.length === 0 ? (
        <text fg={dimText}>None discovered</text>
      ) : (
        <>
          {visible.map((cred) => (
            <box key={cred.id} flexDirection="column">
              <box flexDirection="row" gap={1}>
                {/* Active indicator */}
                <text fg={cred.isActive ? yellowText : dimText}>
                  {cred.isActive ? "★" : " "}
                </text>
                {/* Username:redacted */}
                <text fg={cred.isActive ? greenAccent : dimText}>
                  {cred.username}:{redactSecret(cred.secret)}
                </text>
                {/* Scope */}
                <text fg={blueText}>({cred.scope})</text>
              </box>
              {/* Source on next line if active */}
              {cred.isActive && cred.source && (
                <text fg={dimText}>  from: {truncate(cred.source, 18)}</text>
              )}
            </box>
          ))}
          {remaining > 0 && (
            <text fg={dimText}>... +{remaining} more</text>
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
  return "****";  // Full redaction for security
}

function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + "...";
}
