/**
 * Surface Panel
 *
 * Attack surface panel showing discovered endpoints with status markers.
 */

import { RGBA } from "@opentui/core";
import type { Endpoint, EndpointStatus } from "../../../operator-dashboard/types";

const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);
const greenAccent = RGBA.fromInts(76, 175, 80, 255);
const blueText = RGBA.fromInts(100, 181, 246, 255);
const yellowText = RGBA.fromInts(255, 235, 59, 255);
const orangeText = RGBA.fromInts(255, 152, 0, 255);
const redText = RGBA.fromInts(244, 67, 54, 255);

interface SurfacePanelProps {
  endpoints: Endpoint[];
  maxVisible?: number;
}

export function SurfacePanel({ endpoints, maxVisible = 5 }: SurfacePanelProps) {
  const visible = endpoints.slice(0, maxVisible);
  const remaining = endpoints.length - maxVisible;

  return (
    <box flexDirection="column" gap={1}>
      <text fg={creamText}>
        Attack Surface{" "}
        {endpoints.length > 0 && (
          <span fg={dimText}>({endpoints.length})</span>
        )}
      </text>

      {endpoints.length === 0 ? (
        <text fg={dimText}>No endpoints discovered</text>
      ) : (
        <>
          {visible.map((ep) => (
            <box key={ep.id} flexDirection="row" gap={1}>
              <text fg={getStatusColor(ep.status)}>
                {getStatusMarker(ep.status)}
              </text>
              <text fg={getMethodColor(ep.method)}>
                {ep.method.padEnd(4)}
              </text>
              <text fg={dimText}>{truncatePath(ep.path, 14)}</text>
              {ep.status === "confirmed" && ep.vulnType && (
                <text fg={greenAccent}>{ep.vulnType}</text>
              )}
              {ep.status === "clean" && (
                <text fg={dimText}>clean</text>
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

function getStatusMarker(status?: EndpointStatus): string {
  switch (status) {
    case "confirmed":
      return "✔";
    case "suspicious":
      return "⚠";
    case "clean":
      return "✖";
    case "blocked":
      return "⊘";
    case "untested":
    default:
      return " ";
  }
}

function getStatusColor(status?: EndpointStatus) {
  switch (status) {
    case "confirmed":
      return greenAccent;
    case "suspicious":
      return yellowText;
    case "clean":
      return dimText;
    case "blocked":
      return orangeText;
    case "untested":
    default:
      return dimText;
  }
}

function getMethodColor(method: string) {
  switch (method.toUpperCase()) {
    case "GET":
      return greenAccent;
    case "POST":
      return blueText;
    case "PUT":
    case "PATCH":
      return orangeText;
    case "DELETE":
      return redText;
    default:
      return dimText;
  }
}

function truncatePath(path: string, maxLen: number): string {
  if (path.length <= maxLen) return path;
  return path.slice(0, maxLen - 3) + "...";
}

export default SurfacePanel;
