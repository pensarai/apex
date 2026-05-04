/**
 * Tier badge — `[T<n> | <intent>]` colored by risk tier.
 *
 * Single source of truth for how an approval's tier/intent is displayed
 * across the chat inline prompt, the chat input area, and the operator
 * dashboard's shared approval components.
 */

import { getTierColor, useTheme } from "../../theme";
import { PERMISSION_TIERS, type PendingApproval } from "../../../core/operator";

export function TierBadge({ approval }: { approval: PendingApproval }) {
  const { colors } = useTheme();
  const tier = PERMISSION_TIERS[approval.tier];
  return (
    <text
      fg={getTierColor(colors, approval.tier)}
      content={`[${tier.shortName} | ${approval.intent}]`}
    />
  );
}
