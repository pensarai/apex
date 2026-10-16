import { useKeyboard } from "@opentui/react";
import { useCallback, useState } from "react";
import type { FindingPolicy } from "../../../core/agents/offSecAgent";
import { useConfig } from "../../context/config";
import { Dialog } from "../../context/dialog";
import { useTheme } from "../../theme";
import DialogLayout from "../dialog-layout";

const FINDING_POLICIES: { value: FindingPolicy; label: string }[] = [
  { value: "native", label: "Apex judge (default)" },
  { value: "external", label: "Off (report findings only)" },
];

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
  const [draftFindingPolicy, setDraftFindingPolicy] = useState<FindingPolicy>(
    config.data.findingPolicy ?? "native",
  );
  const [findingSelectOpen, setFindingSelectOpen] = useState(false);
  const [highlightedFindingIndex, setHighlightedFindingIndex] = useState(0);

  const openFindingSelect = useCallback(() => {
    setHighlightedFindingIndex(
      Math.max(
        0,
        FINDING_POLICIES.findIndex(
          (option) => option.value === draftFindingPolicy,
        ),
      ),
    );
    setFindingSelectOpen(true);
  }, [draftFindingPolicy]);

  const saveSettings = useCallback(async () => {
    if (saving) return;

    setSaving(true);
    setError(null);
    try {
      await config.update({
        strikeMode: draftStrikeMode,
        findingPolicy: draftFindingPolicy,
      });
      onClose();
    } catch (cause) {
      setError(
        cause instanceof Error
          ? `Could not save advanced settings: ${cause.message}`
          : "Could not save advanced settings.",
      );
      setSaving(false);
    }
  }, [config, draftFindingPolicy, draftStrikeMode, onClose, saving]);

  useKeyboard((key) => {
    if (findingSelectOpen) {
      key.preventDefault();

      if (key.name === "escape") {
        setFindingSelectOpen(false);
        return;
      }

      if (key.name === "up" || key.name === "down") {
        const direction = key.name === "up" ? -1 : 1;
        setHighlightedFindingIndex(
          (index) =>
            (index + direction + FINDING_POLICIES.length) %
            FINDING_POLICIES.length,
        );
        return;
      }

      if (key.name === "return") {
        const selected = FINDING_POLICIES[highlightedFindingIndex];
        if (selected) setDraftFindingPolicy(selected.value);
        setFindingSelectOpen(false);
      }
      return;
    }

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

    if ((key.name === "j" || key.name === "J") && !key.ctrl && !key.meta) {
      key.preventDefault();
      openFindingSelect();
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
        escLabel={findingSelectOpen ? "back" : "close"}
        footerActions={[
          findingSelectOpen
            ? { key: "Enter", label: "Select", variant: "primary" }
            : { key: "Enter", label: "Save", variant: "primary" },
          findingSelectOpen
            ? { key: "↑/↓", label: "Choose" }
            : { key: "Tab", label: "Strike" },
          ...(!findingSelectOpen ? [{ key: "J", label: "Judge" }] : []),
        ]}
      >
        <box flexDirection="column" gap={1} overflow="hidden">
          <box
            flexDirection="row"
            justifyContent="space-between"
            overflow="hidden"
            onMouseDown={() => setDraftStrikeMode((enabled) => !enabled)}
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

          <box
            flexDirection="row"
            justifyContent="space-between"
            overflow="hidden"
            onMouseDown={openFindingSelect}
          >
            <text fg={colors.text}>Finding judge</text>
            <text
              fg={
                draftFindingPolicy === "native"
                  ? colors.primary
                  : colors.warning
              }
            >
              {draftFindingPolicy === "native" ? "Apex judge" : "Disabled"} ▾
            </text>
          </box>

          {findingSelectOpen && (
            <box flexDirection="column" overflow="hidden">
              {FINDING_POLICIES.map((option, index) => {
                const highlighted = index === highlightedFindingIndex;
                return (
                  <box
                    key={option.value}
                    flexDirection="row"
                    paddingLeft={1}
                    paddingRight={1}
                    overflow="hidden"
                    backgroundColor={
                      highlighted ? colors.backgroundSelected : undefined
                    }
                    onMouseDown={() => {
                      setDraftFindingPolicy(option.value);
                      setFindingSelectOpen(false);
                    }}
                  >
                    <text fg={highlighted ? colors.primary : colors.text}>
                      {highlighted ? "❯ " : "  "}
                      {option.label}
                    </text>
                    {draftFindingPolicy === option.value && (
                      <text fg={colors.primary}> ✓</text>
                    )}
                  </box>
                );
              })}
            </box>
          )}

          <text fg={colors.textMuted}>
            Disabled skips Apex's in-run finding judge and report. The TUI does
            not invoke an external evaluator.
          </text>
          <text fg={colors.textMuted}>
            Applies to new operator sessions. Existing sessions keep their saved
            settings.
          </text>

          {saving && <text fg={colors.textMuted}>Saving…</text>}
          {error && <text fg={colors.error}>{error}</text>}
        </box>
      </DialogLayout>
    </Dialog>
  );
}
