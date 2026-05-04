/**
 * Intent badge — `[safe]` / `[destructive]` colored by classification.
 *
 * Single source of truth for how an approval's intent is displayed
 * across the chat inline prompt, the chat input area, and the operator
 * dashboard's shared approval components.
 */

import { getIntentColor, useTheme } from "../../theme";
import type { PendingApproval } from "../../../core/operator";

export function IntentBadge({ approval }: { approval: PendingApproval }) {
  const { colors } = useTheme();
  const intent = approval.classification.intent;
  return <text fg={getIntentColor(colors, intent)} content={`[${intent}]`} />;
}
