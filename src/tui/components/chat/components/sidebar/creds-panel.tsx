/**
 * Credentials Panel
 *
 * Shows discovered credentials with redacted secrets.
 */

import { RGBA } from "@opentui/core";
import type { Credential } from "../../../operator-dashboard/types";

const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);
const greenAccent = RGBA.fromInts(76, 175, 80, 255);
const yellowText = RGBA.fromInts(255, 235, 59, 255);

interface CredsPanelProps {
  credentials: Credential[];
  maxVisible?: number;
}

export function CredsPanel({ credentials, maxVisible = 5 }: CredsPanelProps) {
  const visible = credentials.slice(0, maxVisible);
  const remaining = credentials.length - maxVisible;

  return (
    <box flexDirection="column" gap={1}>
      <text fg={creamText}>
        Credentials{" "}
        {credentials.length > 0 && (
          <span fg={dimText}>({credentials.length})</span>
        )}
      </text>

      {credentials.length === 0 ? (
        <text fg={dimText}>No credentials found</text>
      ) : (
        <>
          {visible.map((cred) => (
            <box key={cred.id} flexDirection="column" gap={0}>
              <box flexDirection="row" gap={1}>
                {cred.isActive && <text fg={yellowText}>★</text>}
                <text fg={greenAccent}>{cred.username}</text>
                <text fg={dimText}>:</text>
                <text fg={dimText}>{redactSecret(cred.secret)}</text>
              </box>
              <box flexDirection="row" gap={1} marginLeft={2}>
                <text fg={dimText}>{cred.type}</text>
                <text fg={dimText}>·</text>
                <text fg={dimText}>{cred.scope}</text>
              </box>
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
 * Redact secret for display
 */
function redactSecret(secret: string): string {
  if (secret.length <= 4) return "****";
  return secret.slice(0, 2) + "****" + secret.slice(-2);
}

export default CredsPanel;
