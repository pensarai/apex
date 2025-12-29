import { RGBA } from "@opentui/core";
import type { HITLMode, PermissionTier } from "../../../core/hitl";
import { HITL_MODES, PERMISSION_TIERS } from "../../../core/hitl";

const greenBg = RGBA.fromInts(76, 175, 80, 255);
const yellowBg = RGBA.fromInts(255, 235, 59, 255);
const blueBg = RGBA.fromInts(100, 181, 246, 255);
const darkText = RGBA.fromInts(0, 0, 0, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);

interface ModeBannerProps {
  mode: HITLMode;
  autoApproveTier: PermissionTier;
}

export default function ModeBanner({ mode, autoApproveTier }: ModeBannerProps) {
  const modeDef = HITL_MODES[mode];
  const tierDef = PERMISSION_TIERS[autoApproveTier];

  const bgColor = mode === "plan" ? yellowBg : mode === "auto" ? greenBg : blueBg;

  return (
    <box flexDirection="row" gap={2} alignItems="center">
      <box backgroundColor={bgColor} paddingLeft={1} paddingRight={1}>
        <text fg={darkText}>{modeDef.name.toUpperCase()}</text>
      </box>
      {mode === "auto" && (
        <text fg={dimText}>
          Auto-approve: T1-T{autoApproveTier} ({tierDef.name})
        </text>
      )}
      {mode === "manual" && (
        <text fg={dimText}>
          T1 auto, T2-T5 require approval
        </text>
      )}
      {mode === "plan" && (
        <text fg={dimText}>
          Read-only - network actions blocked
        </text>
      )}
      <text fg={dimText}>[M] Change mode</text>
    </box>
  );
}
