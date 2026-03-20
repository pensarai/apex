/**
 * DialogControls — Shared footer control hints for dialogs and views.
 *
 * Renders a horizontal row of keyboard shortcut hints separated by ` · `.
 * Supports three visual tiers via the `variant` prop on each control item:
 *
 * - `"default"` (implicit) — `colors.textMuted` key color. Use for secondary
 *   and navigation actions (↑/↓, Esc, Tab, etc.).
 * - `"primary"` — `colors.primary` key color. Use for the main CTA — typically
 *   one per dialog (Enter to confirm/submit).
 * - `"danger"` — `colors.error` key color. Use for irreversible actions
 *   (Delete, Disconnect).
 *
 * Labels are always `colors.textMuted` regardless of variant.
 *
 * ## Capitalization conventions
 *
 * - Named keys: Title Case — `Enter`, `Esc`, `Tab`, `Space`
 * - Single letter keys: Uppercase — `D`, `R`, `M`, `O`, `E`
 * - Arrows: `↑/↓`, `←/→`
 * - Combos: `Ctrl+D`, `Ctrl+P`
 * - Labels: Title Case — `Open in Editor`, `Go Back`
 *
 * ## Ordering convention (enforced by caller)
 *
 * 1. Navigation (↑/↓, Tab)
 * 2. Primary action (Enter)
 * 3. Secondary actions (letter keys)
 * 4. Danger actions (D, Ctrl+D)
 * 5. Dismiss (Esc) — always last
 */

import { useTheme } from "../../theme";

export interface ControlItem {
  /** Key name displayed in brackets, e.g. "Enter", "Esc", "↑/↓", "D", "Ctrl+D" */
  key: string;
  /** Action label, e.g. "Confirm", "Close", "Navigate" */
  label: string;
  /** Visual variant: "default" (muted), "primary" (bright CTA), "danger" (red) */
  variant?: "default" | "primary" | "danger";
}

export interface DialogControlsProps {
  /** Ordered list of control items to display */
  controls: ControlItem[];
}

export function DialogControls({ controls }: DialogControlsProps) {
  const { colors } = useTheme();

  if (controls.length === 0) return null;

  const keyColor = (variant: ControlItem["variant"]) => {
    switch (variant) {
      case "primary":
        return colors.primary;
      case "danger":
        return colors.error;
      default:
        return colors.textMuted;
    }
  };

  return (
    <text fg={colors.textMuted}>
      {controls.map((control, i) => (
        <span key={i}>
          {i > 0 && " · "}
          <span fg={keyColor(control.variant)}>[{control.key}]</span>
          {" " + control.label}
        </span>
      ))}
    </text>
  );
}
