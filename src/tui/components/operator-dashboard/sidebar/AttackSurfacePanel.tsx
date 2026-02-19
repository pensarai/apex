/**
 * Attack Surface Panel - Shows discovered endpoints with status markers
 * Markers: ✔ confirmed, ⚠ suspicious, ✖ clean, ⊘ blocked, (space) untested
 */

import type { RGBA } from "@opentui/core";
import type { Endpoint, EndpointStatus } from "../types";
import { useTheme, type ThemeColors } from "../../../theme";

interface AttackSurfacePanelProps {
  endpoints: Endpoint[];
  maxVisible?: number;
}

export function AttackSurfacePanel({
  endpoints,
  maxVisible = 5,
}: AttackSurfacePanelProps) {
  const { colors } = useTheme();
  const visible = endpoints.slice(0, maxVisible);
  const remaining = endpoints.length - maxVisible;

  return (
    <box flexDirection="column" gap={1}>
      <text fg={colors.text}>
        Attack Surface{" "}
        {endpoints.length > 0 && (
          <span fg={colors.textMuted}>({endpoints.length})</span>
        )}
      </text>

      {endpoints.length === 0 ? (
        <text fg={colors.textMuted}>No endpoints discovered</text>
      ) : (
        <>
          {visible.map((ep) => (
            <box key={ep.id} flexDirection="row" gap={1}>
              {/* Status marker */}
              <text fg={getStatusColor(colors, ep.status)}>
                {getStatusMarker(ep.status)}
              </text>
              {/* Method */}
              <text fg={getMethodColor(colors, ep.method)}>
                {ep.method.padEnd(4)}
              </text>
              {/* Path */}
              <text fg={colors.textMuted}>{truncatePath(ep.path, 14)}</text>
              {/* Vuln type if confirmed */}
              {ep.status === "confirmed" && ep.vulnType && (
                <text fg={colors.primary}>{ep.vulnType}</text>
              )}
              {/* Show "clean" text if clean */}
              {ep.status === "clean" && (
                <text fg={colors.textMuted}>clean</text>
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
function getStatusColor(colors: ThemeColors, status?: EndpointStatus): RGBA {
  switch (status) {
    case "confirmed":
      return colors.primary;
    case "suspicious":
      return colors.warning;
    case "clean":
      return colors.textMuted;
    case "blocked":
      return colors.tierRisky;
    case "untested":
    default:
      return colors.textMuted;
  }
}

function getMethodColor(colors: ThemeColors, method: string): RGBA {
  switch (method.toUpperCase()) {
    case "GET":
      return colors.primary;
    case "POST":
      return colors.accent;
    case "PUT":
    case "PATCH":
      return colors.tierRisky;
    case "DELETE":
      return colors.error;
    default:
      return colors.textMuted;
  }
}

function truncatePath(path: string, maxLen: number): string {
  if (path.length <= maxLen) return path;
  return path.slice(0, maxLen - 3) + "...";
}
