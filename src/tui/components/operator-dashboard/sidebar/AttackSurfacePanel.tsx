/**
 * Attack Surface Panel - Shows discovered endpoints
 */

import { RGBA } from "@opentui/core";
import type { Endpoint } from "../types";

const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);
const greenAccent = RGBA.fromInts(76, 175, 80, 255);
const blueText = RGBA.fromInts(100, 181, 246, 255);

interface AttackSurfacePanelProps {
  endpoints: Endpoint[];
  maxVisible?: number;
}

export function AttackSurfacePanel({ endpoints, maxVisible = 6 }: AttackSurfacePanelProps) {
  const visible = endpoints.slice(0, maxVisible);
  const remaining = endpoints.length - maxVisible;

  return (
    <box flexDirection="column" gap={1}>
      <text fg={creamText}>
        Attack Surface {endpoints.length > 0 && <span fg={dimText}>({endpoints.length})</span>}
      </text>

      {endpoints.length === 0 ? (
        <text fg={dimText}>No endpoints discovered</text>
      ) : (
        <>
          {visible.map((ep) => (
            <box key={ep.id} flexDirection="row" gap={1}>
              <text fg={getMethodColor(ep.method)}>{ep.method.padEnd(4)}</text>
              <text fg={dimText}>{truncatePath(ep.path, 20)}</text>
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

function getMethodColor(method: string) {
  switch (method.toUpperCase()) {
    case "GET":
      return greenAccent;
    case "POST":
      return blueText;
    case "PUT":
    case "PATCH":
      return RGBA.fromInts(255, 152, 0, 255); // orange
    case "DELETE":
      return RGBA.fromInts(244, 67, 54, 255); // red
    default:
      return dimText;
  }
}

function truncatePath(path: string, maxLen: number): string {
  if (path.length <= maxLen) return path;
  return path.slice(0, maxLen - 3) + "...";
}
