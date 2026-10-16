import { useKeyboard } from "@opentui/react";
import { useCallback, useState } from "react";
import type { FindingPolicy } from "../../../core/agents/offSecAgent";
import { useConfig } from "../../context/config";
import { Dialog } from "../../context/dialog";
import { useDimensions } from "../../context/dimensions";
import { useTheme } from "../../theme";
import DialogLayout from "../dialog-layout";

const FINDING_POLICIES: { value: FindingPolicy; label: string }[] = [
  { value: "native", label: "Apex judge (default)" },
  { value: "external", label: "Off (report findings only)" },
];

interface AdvancedSettingsProps {
  onClose: () => void;
}

type FocusedSetting = "strike" | "judge" | "save";

export default function AdvancedSettings({ onClose }: AdvancedSettingsProps) {
  const { colors } = useTheme();
  const dimensions = useDimensions();
  const compact = dimensions.width < 65 || dimensions.height < 24;
  const config = useConfig();
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [draftStrikeMode, setDraftStrikeMode] = useState(
    config.data.strikeMode ?? false,
  );
  const [draftFindingPolicy, setDraftFindingPolicy] = useState<FindingPolicy>(
    config.data.strikeMode ? (config.data.findingPolicy ?? "native") : "native",
  );
  const [findingSelectOpen, setFindingSelectOpen] = useState(false);
  const [highlightedFindingIndex, setHighlightedFindingIndex] = useState(0);
  const [focusedSetting, setFocusedSetting] =
    useState<FocusedSetting>("strike");

  const openFindingSelect = useCallback(() => {
    if (!draftStrikeMode) return;
    setHighlightedFindingIndex(
      Math.max(
        0,
        FINDING_POLICIES.findIndex(
          (option) => option.value === draftFindingPolicy,
        ),
      ),
    );
    setFindingSelectOpen(true);
  }, [draftFindingPolicy, draftStrikeMode]);

  const toggleStrikeMode = useCallback(() => {
    if (draftStrikeMode) {
      setDraftFindingPolicy("native");
      setFindingSelectOpen(false);
      setFocusedSetting((focused) =>
        focused === "judge" ? "strike" : focused,
      );
    }
    setDraftStrikeMode(!draftStrikeMode);
  }, [draftStrikeMode]);

  const moveFocus = useCallback(
    (direction: number) => {
      const visibleSettings: FocusedSetting[] = draftStrikeMode
        ? ["strike", "judge", "save"]
        : ["strike", "save"];
      setFocusedSetting((focused) => {
        const currentIndex = Math.max(0, visibleSettings.indexOf(focused));
        const nextIndex =
          (currentIndex + direction + visibleSettings.length) %
          visibleSettings.length;
        return visibleSettings[nextIndex] ?? "strike";
      });
    },
    [draftStrikeMode],
  );

  const saveSettings = useCallback(async () => {
    if (saving) return;

    setSaving(true);
    setError(null);
    try {
      await config.update({
        strikeMode: draftStrikeMode,
        findingPolicy: draftStrikeMode ? draftFindingPolicy : "native",
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
    if (key.name === "tab") {
      key.preventDefault();
      toggleStrikeMode();
      return;
    }

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

    if (key.name === "up" || key.name === "down") {
      key.preventDefault();
      moveFocus(key.name === "up" ? -1 : 1);
      return;
    }

    if (key.name === "return") {
      key.preventDefault();
      if (focusedSetting === "strike") toggleStrikeMode();
      else if (focusedSetting === "judge") openFindingSelect();
      else void saveSettings();
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
            : { key: "Enter", label: "Activate", variant: "primary" },
          findingSelectOpen
            ? { key: "↑/↓", label: "Choose" }
            : { key: "↑/↓", label: "Navigate" },
          ...(dimensions.width >= 60 ? [{ key: "Tab", label: "Strike" }] : []),
        ]}
      >
        <box flexDirection="column" gap={compact ? 0 : 1} overflow="hidden">
          <box
            flexDirection="row"
            justifyContent="space-between"
            overflow="hidden"
            backgroundColor={
              focusedSetting === "strike" && !findingSelectOpen
                ? colors.backgroundSelected
                : undefined
            }
            onMouseDown={() => {
              setFocusedSetting("strike");
              toggleStrikeMode();
            }}
          >
            <text
              fg={focusedSetting === "strike" ? colors.primary : colors.text}
            >
              {focusedSetting === "strike" ? "❯ " : "  "}Strike Mode
            </text>
            <text fg={draftStrikeMode ? colors.warning : colors.textMuted}>
              {draftStrikeMode ? "● Enabled" : "○ Disabled"}
            </text>
          </box>

          {!compact && (
            <text fg={colors.textMuted}>
              Focused research; no auto-discovery or agent fan-out.
            </text>
          )}

          {draftStrikeMode && (
            <>
              <box
                flexDirection="row"
                justifyContent="space-between"
                overflow="hidden"
                backgroundColor={
                  focusedSetting === "judge" && !findingSelectOpen
                    ? colors.backgroundSelected
                    : undefined
                }
                onMouseDown={() => {
                  setFocusedSetting("judge");
                  openFindingSelect();
                }}
              >
                <text
                  fg={focusedSetting === "judge" ? colors.primary : colors.text}
                >
                  {focusedSetting === "judge" ? "❯ " : "  "}Finding judge
                </text>
                <text
                  fg={
                    draftFindingPolicy === "native"
                      ? colors.primary
                      : colors.warning
                  }
                >
                  {draftFindingPolicy === "native" ? "Apex judge" : "Disabled"}
                  {" ▾"}
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

              {!compact && (
                <>
                  <text fg={colors.textMuted}>
                    Judge off skips in-run review and report.
                  </text>
                  <text fg={colors.textMuted}>
                    New sessions only; TUI has no external evaluator.
                  </text>
                </>
              )}
            </>
          )}

          <box
            flexDirection="row"
            overflow="hidden"
            backgroundColor={
              focusedSetting === "save" && !findingSelectOpen
                ? colors.backgroundSelected
                : undefined
            }
            onMouseDown={() => {
              setFocusedSetting("save");
              void saveSettings();
            }}
          >
            <text fg={focusedSetting === "save" ? colors.primary : colors.text}>
              {focusedSetting === "save" ? "❯ " : "  "}Save settings
            </text>
          </box>

          {saving && <text fg={colors.textMuted}>Saving…</text>}
          {error && <text fg={colors.error}>{error}</text>}
        </box>
      </DialogLayout>
    </Dialog>
  );
}
