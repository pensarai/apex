/**
 * Collapsible Sidebar
 *
 * Container with collapse animation for chat sidebar.
 * Toggle with Ctrl+B.
 */

import { useState, useEffect, useMemo } from "react";
import { RGBA } from "@opentui/core";
import { TargetPanel } from "./target-panel";
import { SurfacePanel } from "./surface-panel";
import { CredsPanel } from "./creds-panel";
import { VulnsPanel } from "./vulns-panel";
import type { Endpoint, VerifiedVuln, Credential } from "../../../operator-dashboard/types";

// Colors
const dimText = RGBA.fromInts(120, 120, 120, 255);
const borderColor = RGBA.fromInts(60, 60, 60, 255);

export interface SidebarState {
  targetHost: string;
  ports: { port: number; service?: string }[];
  attackSurface: Endpoint[];
  credentials: Credential[];
  verifiedVulns: VerifiedVuln[];
}

interface CollapsibleSidebarProps {
  collapsed: boolean;
  onToggle?: () => void;
  state: SidebarState;
  width?: number | `${number}%` | "auto";
}

export function CollapsibleSidebar({
  collapsed,
  onToggle,
  state,
  width = "30%",
}: CollapsibleSidebarProps) {
  // Don't render content when collapsed
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
      borderColor={borderColor}
    >
      {/* Target state - host and ports */}
      <TargetPanel
        host={state.targetHost}
        ports={state.ports}
      />

      {/* Attack surface - discovered endpoints */}
      <SurfacePanel
        endpoints={state.attackSurface}
        maxVisible={4}
      />

      {/* Credentials - discovered creds */}
      <CredsPanel
        credentials={state.credentials}
        maxVisible={3}
      />

      {/* Verified vulnerabilities */}
      <VulnsPanel
        vulns={state.verifiedVulns}
        maxVisible={3}
      />
    </box>
  );
}

/**
 * Collapsed sidebar indicator
 * Shows a minimal indicator when sidebar is collapsed
 */
export function CollapsedSidebarIndicator({
  onToggle,
  hasFindings,
}: {
  onToggle?: () => void;
  hasFindings?: boolean;
}) {
  return (
    <box
      flexDirection="column"
      paddingLeft={1}
      paddingRight={1}
      border={["left"]}
      borderColor={borderColor}
      onMouseDown={onToggle}
    >
      <text fg={hasFindings ? RGBA.fromInts(76, 175, 80, 255) : dimText}>
        {hasFindings ? "▶" : "│"}
      </text>
    </box>
  );
}

/**
 * Hook to manage sidebar state with persistence
 */
export function useSidebarState(sessionId?: string) {
  const [collapsed, setCollapsed] = useState(true); // Default hidden
  const [state, setState] = useState<SidebarState>({
    targetHost: "",
    ports: [],
    attackSurface: [],
    credentials: [],
    verifiedVulns: [],
  });

  // Load persisted state
  useEffect(() => {
    if (!sessionId) return;

    // Could load from localStorage or session storage here
    const key = `sidebar-collapsed-${sessionId}`;
    const saved = typeof localStorage !== "undefined" ? localStorage.getItem(key) : null;
    if (saved !== null) {
      setCollapsed(saved === "true");
    }
  }, [sessionId]);

  // Persist collapsed state
  const toggleCollapsed = () => {
    setCollapsed((prev) => {
      const next = !prev;
      if (sessionId && typeof localStorage !== "undefined") {
        localStorage.setItem(`sidebar-collapsed-${sessionId}`, String(next));
      }
      return next;
    });
  };

  const updateState = (updates: Partial<SidebarState>) => {
    setState((prev) => ({ ...prev, ...updates }));
  };

  return {
    collapsed,
    toggleCollapsed,
    state,
    updateState,
    hasFindings: state.verifiedVulns.length > 0,
  };
}

export default CollapsibleSidebar;
