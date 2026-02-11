/**
 * Attack Surface Panel - Shows discovered endpoints with status markers
 * Markers: ✔ confirmed, ⚠ suspicious, ✖ clean, ⊘ blocked, (space) untested
 */

import type { Endpoint, EndpointStatus } from "../types";
import { useColors, type ThemeColors } from "../../../theme";

interface AttackSurfacePanelProps {
  endpoints: Endpoint[];
  maxVisible?: number;
}

export function AttackSurfacePanel({ endpoints, maxVisible = 5 }: AttackSurfacePanelProps) {
  const colors = useColors();
  const { creamText, dimText, greenAccent } = colors;
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
              {/* Status marker */}
              <text fg={getStatusColor(ep.status, colors)}>{getStatusMarker(ep.status)}</text>
              {/* Method */}
              <text fg={getMethodColor(ep.method, colors)}>{ep.method.padEnd(4)}</text>
              {/* Path */}
              <text fg={dimText}>{truncatePath(ep.path, 14)}</text>
              {/* Vuln type if confirmed */}
              {ep.status === 'confirmed' && ep.vulnType && (
                <text fg={greenAccent}>{ep.vulnType}</text>
              )}
              {/* Show "clean" text if clean */}
              {ep.status === 'clean' && (
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

/**
 * Get status marker character
 */
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

/**
 * Get color for status marker
 */
function getStatusColor(status: EndpointStatus | undefined, colors: ThemeColors) {
  switch (status) {
    case "confirmed":
      return colors.greenAccent;
    case "suspicious":
      return colors.yellowText;
    case "clean":
      return colors.dimText;
    case "blocked":
      return colors.orangeText;
    case "untested":
    default:
      return colors.dimText;
  }
}

function getMethodColor(method: string, colors: ThemeColors) {
  switch (method.toUpperCase()) {
    case "GET":
      return colors.greenAccent;
    case "POST":
      return colors.toolColor;
    case "PUT":
    case "PATCH":
      return colors.orangeText;
    case "DELETE":
      return colors.redText;
    default:
      return colors.dimText;
  }
}

function truncatePath(path: string, maxLen: number): string {
  if (path.length <= maxLen) return path;
  return path.slice(0, maxLen - 3) + "...";
}
