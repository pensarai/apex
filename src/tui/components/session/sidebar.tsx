/**
 * Session Sidebar Component
 *
 * Collapsible sidebar showing session context:
 * - Target state
 * - Attack surface
 * - Credentials
 * - Verified vulnerabilities
 */

import { useState, useEffect, useCallback } from "react";
import { colors } from "../../theme";
import type { Endpoint, VerifiedVuln, Credential } from "../operator-dashboard/types";

// ============================================
// Sidebar State Types
// ============================================

export interface SidebarState {
  targetHost: string;
  ports: { port: number; service?: string }[];
  attackSurface: Endpoint[];
  credentials: Credential[];
  verifiedVulns: VerifiedVuln[];
}

export const initialSidebarState: SidebarState = {
  targetHost: "",
  ports: [],
  attackSurface: [],
  credentials: [],
  verifiedVulns: [],
};

// ============================================
// Main Sidebar Component
// ============================================

interface SidebarProps {
  collapsed: boolean;
  state: SidebarState;
  width?: number | `${number}%` | "auto";
}

/**
 * Collapsible sidebar for session context
 */
export function Sidebar({ collapsed, state, width = "30%" }: SidebarProps) {
  if (collapsed) {
    return null;
  }

  return (
    <box
      flexDirection="column"
      width={width}
      paddingLeft={2}
      paddingRight={2}
      gap={2}
      border={["left"]}
      borderColor={colors.dimText}
    >
      {/* Target state - host and ports */}
      <TargetPanel host={state.targetHost} ports={state.ports} />

      {/* Attack surface - discovered endpoints */}
      <AttackSurfacePanel endpoints={state.attackSurface} maxVisible={4} />

      {/* Credentials - discovered creds */}
      <CredentialsPanel credentials={state.credentials} maxVisible={3} />

      {/* Verified vulnerabilities */}
      <VulnsPanel vulns={state.verifiedVulns} maxVisible={3} />
    </box>
  );
}

// ============================================
// Target Panel
// ============================================

interface TargetPanelProps {
  host: string;
  ports: { port: number; service?: string }[];
}

function TargetPanel({ host, ports }: TargetPanelProps) {
  const portsStr =
    ports.length > 0 ? ports.map((p) => p.port).join(", ") : "—";

  return (
    <box flexDirection="column" gap={1}>
      <text fg={colors.creamText}>Target</text>
      <text fg={colors.greenAccent}>{host || "Not configured"}</text>
      <box flexDirection="row" gap={1}>
        <text fg={colors.dimText}>Ports:</text>
        <text fg={colors.dimText}>{portsStr}</text>
      </box>
    </box>
  );
}

// ============================================
// Attack Surface Panel
// ============================================

interface AttackSurfacePanelProps {
  endpoints: Endpoint[];
  maxVisible?: number;
}

function AttackSurfacePanel({ endpoints, maxVisible = 4 }: AttackSurfacePanelProps) {
  const [expanded, setExpanded] = useState(false);
  const visibleEndpoints = expanded ? endpoints : endpoints.slice(0, maxVisible);
  const hasMore = endpoints.length > maxVisible;

  // Status indicator icons
  const getStatusIcon = (status?: string) => {
    switch (status) {
      case "confirmed":
        return { icon: "!", color: colors.redText };
      case "suspicious":
        return { icon: "?", color: colors.yellowText };
      case "clean":
        return { icon: "✓", color: colors.greenAccent };
      case "blocked":
        return { icon: "✗", color: colors.dimText };
      default:
        return { icon: "·", color: colors.dimText };
    }
  };

  return (
    <box flexDirection="column" gap={1}>
      <text fg={colors.creamText}>
        Attack Surface ({endpoints.length})
      </text>

      {endpoints.length === 0 ? (
        <text fg={colors.dimText}>No endpoints discovered</text>
      ) : (
        <>
          {visibleEndpoints.map((ep, idx) => {
            const { icon, color } = getStatusIcon(ep.status);
            return (
              <box key={ep.id || idx} flexDirection="row" gap={1}>
                <text fg={color}>{icon}</text>
                <text fg={colors.dimText}>{ep.method}</text>
                <text fg={colors.creamText}>{ep.path}</text>
                {ep.vulnType && (
                  <text fg={colors.redText}>({ep.vulnType})</text>
                )}
              </box>
            );
          })}
          {hasMore && !expanded && (
            <box onMouseDown={() => setExpanded(true)}>
              <text fg={colors.dimText}>
                +{endpoints.length - maxVisible} more...
              </text>
            </box>
          )}
          {expanded && hasMore && (
            <box onMouseDown={() => setExpanded(false)}>
              <text fg={colors.dimText}>Show less</text>
            </box>
          )}
        </>
      )}
    </box>
  );
}

// ============================================
// Credentials Panel
// ============================================

interface CredentialsPanelProps {
  credentials: Credential[];
  maxVisible?: number;
}

function CredentialsPanel({ credentials, maxVisible = 3 }: CredentialsPanelProps) {
  const [expanded, setExpanded] = useState(false);
  const visibleCreds = expanded ? credentials : credentials.slice(0, maxVisible);
  const hasMore = credentials.length > maxVisible;

  // Redact secret for display
  const redactSecret = (secret: string) => {
    if (secret.length <= 4) return "****";
    return secret.slice(0, 2) + "****" + secret.slice(-2);
  };

  return (
    <box flexDirection="column" gap={1}>
      <text fg={colors.creamText}>
        Credentials ({credentials.length})
      </text>

      {credentials.length === 0 ? (
        <text fg={colors.dimText}>No credentials found</text>
      ) : (
        <>
          {visibleCreds.map((cred, idx) => (
            <box key={cred.id || idx} flexDirection="column">
              <box flexDirection="row" gap={1}>
                {cred.isActive && <text fg={colors.yellowText}>★</text>}
                <text fg={colors.creamText}>{cred.username}</text>
                <text fg={colors.dimText}>:</text>
                <text fg={colors.dimText}>{redactSecret(cred.secret)}</text>
              </box>
              <box flexDirection="row" gap={1} marginLeft={2}>
                <text fg={colors.dimText}>{cred.type}</text>
                <text fg={colors.dimText}>|</text>
                <text fg={colors.dimText}>{cred.scope}</text>
              </box>
            </box>
          ))}
          {hasMore && !expanded && (
            <box onMouseDown={() => setExpanded(true)}>
              <text fg={colors.dimText}>
                +{credentials.length - maxVisible} more...
              </text>
            </box>
          )}
          {expanded && hasMore && (
            <box onMouseDown={() => setExpanded(false)}>
              <text fg={colors.dimText}>Show less</text>
            </box>
          )}
        </>
      )}
    </box>
  );
}

// ============================================
// Vulnerabilities Panel
// ============================================

interface VulnsPanelProps {
  vulns: VerifiedVuln[];
  maxVisible?: number;
}

function VulnsPanel({ vulns, maxVisible = 3 }: VulnsPanelProps) {
  const [expanded, setExpanded] = useState(false);
  const visibleVulns = expanded ? vulns : vulns.slice(0, maxVisible);
  const hasMore = vulns.length > maxVisible;

  // Severity color
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return colors.redText;
      case "high":
        return colors.orangeText;
      case "medium":
        return colors.yellowText;
      case "low":
        return colors.greenAccent;
      default:
        return colors.dimText;
    }
  };

  return (
    <box flexDirection="column" gap={1}>
      <text fg={colors.creamText}>
        Verified Vulns ({vulns.length})
      </text>

      {vulns.length === 0 ? (
        <text fg={colors.dimText}>No vulnerabilities verified</text>
      ) : (
        <>
          {visibleVulns.map((vuln, idx) => (
            <box key={vuln.id || idx} flexDirection="column">
              <box flexDirection="row" gap={1}>
                <text fg={getSeverityColor(vuln.severity)}>
                  [{vuln.severity.toUpperCase().slice(0, 4)}]
                </text>
                <text fg={colors.creamText}>{vuln.type}</text>
              </box>
              <box marginLeft={2}>
                <text fg={colors.dimText}>{vuln.endpoint}</text>
              </box>
            </box>
          ))}
          {hasMore && !expanded && (
            <box onMouseDown={() => setExpanded(true)}>
              <text fg={colors.dimText}>
                +{vulns.length - maxVisible} more...
              </text>
            </box>
          )}
          {expanded && hasMore && (
            <box onMouseDown={() => setExpanded(false)}>
              <text fg={colors.dimText}>Show less</text>
            </box>
          )}
        </>
      )}
    </box>
  );
}

// ============================================
// Sidebar State Hook
// ============================================

/**
 * Hook to manage sidebar state with persistence
 */
export function useSidebarState(sessionId?: string) {
  const [collapsed, setCollapsed] = useState(true); // Default hidden
  const [state, setState] = useState<SidebarState>(initialSidebarState);

  // Load persisted state
  useEffect(() => {
    if (!sessionId) return;

    const key = `sidebar-collapsed-${sessionId}`;
    const saved =
      typeof localStorage !== "undefined" ? localStorage.getItem(key) : null;
    if (saved !== null) {
      setCollapsed(saved === "true");
    }
  }, [sessionId]);

  // Toggle collapsed state
  const toggleCollapsed = useCallback(() => {
    setCollapsed((prev) => {
      const next = !prev;
      if (sessionId && typeof localStorage !== "undefined") {
        localStorage.setItem(`sidebar-collapsed-${sessionId}`, String(next));
      }
      return next;
    });
  }, [sessionId]);

  // Update state
  const updateState = useCallback((updates: Partial<SidebarState>) => {
    setState((prev) => ({ ...prev, ...updates }));
  }, []);

  // Reset state
  const resetState = useCallback(() => {
    setState(initialSidebarState);
  }, []);

  return {
    collapsed,
    setCollapsed,
    toggleCollapsed,
    state,
    updateState,
    resetState,
    hasFindings: state.verifiedVulns.length > 0,
  };
}

export default Sidebar;
