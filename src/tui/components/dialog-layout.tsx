import type { ReactNode } from "react";
import { useTheme } from "../theme";
import { DialogControls, type ControlItem } from "./shared/dialog-controls";

export type { ControlItem as FooterAction };

export interface DialogLayoutProps {
  title: string | ReactNode;
  escLabel?: string | null;
  footerActions?: ControlItem[];
  children: ReactNode;
}

export default function DialogLayout({
  title,
  escLabel = "close",
  footerActions,
  children,
}: DialogLayoutProps) {
  const { colors } = useTheme();

  return (
    <box
      flexDirection="column"
      width="100%"
      paddingLeft={2}
      paddingRight={2}
      paddingTop={1}
      paddingBottom={1}
    >
      {/* Header */}
      <box
        flexDirection="row"
        justifyContent="space-between"
        width="100%"
        flexShrink={0}
      >
        {typeof title === "string" ? (
          <text fg={colors.primary}>{title}</text>
        ) : (
          title
        )}
        {escLabel !== null && (
          <text fg={colors.textMuted}>
            <span fg={colors.textMuted}>[Esc]</span> {escLabel}
          </text>
        )}
      </box>

      {/* Body */}
      <box
        flexDirection="column"
        width="100%"
        marginTop={1}
        flexShrink={1}
        overflow="hidden"
      >
        {children}
      </box>

      {/* Footer */}
      {footerActions && footerActions.length > 0 && (
        <box marginTop={1} flexShrink={0}>
          <DialogControls controls={footerActions} />
        </box>
      )}
    </box>
  );
}
