/**
 * Target State Panel - Externalizes the agent's mental model
 * Shows host, ports, auth state, phase, objective, and focus
 */

import { RGBA } from "@opentui/core";
import type { TargetState, PentestPhase } from "../types";

const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);
const greenAccent = RGBA.fromInts(76, 175, 80, 255);
const yellowText = RGBA.fromInts(255, 235, 59, 255);
const blueText = RGBA.fromInts(100, 181, 246, 255);
const orangeText = RGBA.fromInts(255, 152, 0, 255);

interface TargetStatePanelProps {
  target: TargetState | null;
  onPhaseConfirm?: (confirmed: boolean) => void;
}

export function TargetStatePanel({ target, onPhaseConfirm }: TargetStatePanelProps) {
  if (!target) {
    return (
      <box flexDirection="column" gap={1}>
        <text fg={creamText}>Target State</text>
        <text fg={dimText}>No target set</text>
      </box>
    );
  }

  const phaseColor = getPhaseColor(target.phase);
  const authColor = getAuthColor(target.authState);
  const portsStr = target.ports.length > 0
    ? target.ports.slice(0, 4).map(p => p.port).join(",") + (target.ports.length > 4 ? "..." : "")
    : "scanning...";

  // Show effective objective (user override takes precedence)
  const effectiveObjective = target.objectiveOverride || target.objective;

  return (
    <box flexDirection="column" gap={1}>
      <text fg={creamText}>Target State</text>

      {/* Host */}
      <text fg={greenAccent}>{target.host}</text>

      {/* Ports */}
      <box flexDirection="row" gap={1}>
        <text fg={dimText}>Ports:</text>
        <text fg={dimText}>{portsStr}</text>
      </box>

      {/* Auth State */}
      <box flexDirection="row" gap={1}>
        <text fg={dimText}>Auth:</text>
        <text fg={authColor}>
          {target.authState}
          {target.authDetails && ` (${target.authDetails})`}
        </text>
      </box>

      {/* Phase */}
      <box flexDirection="row" gap={1}>
        <text fg={dimText}>Phase:</text>
        <text fg={phaseColor}>{capitalizePhase(target.phase)}</text>
      </box>

      {/* Objective */}
      <box flexDirection="row" gap={1}>
        <text fg={dimText}>Obj:</text>
        <text fg={dimText}>{truncate(effectiveObjective, 18)}</text>
      </box>

      {/* Focus (if set) */}
      {target.focus && (
        <box flexDirection="row" gap={1}>
          <text fg={dimText}>Focus:</text>
          <text fg={blueText}>{truncate(target.focus, 16)}</text>
        </box>
      )}

      {/* Pending Phase Transition (Y/N confirm) */}
      {target.pendingPhase && (
        <box flexDirection="row" gap={1} marginTop={1}>
          <text fg={yellowText}>{"→"}</text>
          <text fg={yellowText}>{capitalizePhase(target.pendingPhase)}?</text>
          <text fg={dimText}>[Y/N]</text>
        </box>
      )}
    </box>
  );
}

function getPhaseColor(phase: PentestPhase) {
  switch (phase) {
    case "recon":
      return blueText;
    case "foothold":
      return yellowText;
    case "user":
      return orangeText;
    case "root":
      return greenAccent;
    default:
      return dimText;
  }
}

function getAuthColor(auth: string) {
  switch (auth) {
    case "none":
      return dimText;
    case "cookie":
      return yellowText;
    case "creds":
      return orangeText;
    case "shell":
      return greenAccent;
    default:
      return dimText;
  }
}

function capitalizePhase(phase: PentestPhase): string {
  return phase.charAt(0).toUpperCase() + phase.slice(1);
}

function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + "...";
}
