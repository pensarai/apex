import { useKeyboard } from "@opentui/react";
import { useCallback, useState } from "react";
import { useConfig } from "../../context/config";
import { Dialog } from "../../context/dialog";
import { useTheme } from "../../theme";
import DialogLayout from "../dialog-layout";

interface AdvancedSettingsProps {
  onClose: () => void;
}

export default function AdvancedSettings({ onClose }: AdvancedSettingsProps) {
  const { colors } = useTheme();
  const config = useConfig();
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [draftStrikeMode, setDraftStrikeMode] = useState(
    config.data.strikeMode ?? false,
  );

  const saveSettings = useCallback(async () => {
    if (saving) return;

    setSaving(true);
    setError(null);
    try {
      await config.update({ strikeMode: draftStrikeMode });
      onClose();
    } catch (cause) {
      setError(
        cause instanceof Error
          ? `Could not save Strike Mode: ${cause.message}`
          : "Could not save Strike Mode.",
      );
      setSaving(false);
    }
  }, [config, draftStrikeMode, onClose, saving]);

  useKeyboard((key) => {
    if (key.name === "escape") {
      key.preventDefault();
      onClose();
      return;
    }

    if (key.name === "tab") {
      key.preventDefault();
      setDraftStrikeMode((enabled) => !enabled);
      return;
    }

    if (key.name === "return") {
      key.preventDefault();
      void saveSettings();
    }
  });

  return (
    <Dialog size="medium" onClose={onClose}>
      <DialogLayout
        title="Advanced Settings"
        footerActions={[
          { key: "Enter", label: "Save & Close", variant: "primary" },
          { key: "Tab", label: "Toggle" },
        ]}
      >
        <box flexDirection="column" gap={1} overflow="hidden">
          <box
            flexDirection="row"
            justifyContent="space-between"
            overflow="hidden"
          >
            <text fg={colors.text}>Strike Mode</text>
            <text fg={draftStrikeMode ? colors.warning : colors.textMuted}>
              {draftStrikeMode ? "● Enabled" : "○ Disabled"}
            </text>
          </box>

          <text fg={colors.textMuted}>
            Use one focused operator for iterative vulnerability research.
            Disables automatic discovery and agent fan-out.
          </text>
          <text fg={colors.textMuted}>
            Applies to new operator sessions. Existing sessions keep their saved
            mode.
          </text>

          {saving && <text fg={colors.textMuted}>Saving…</text>}
          {error && <text fg={colors.error}>{error}</text>}
        </box>
      </DialogLayout>
    </Dialog>
  );
}
