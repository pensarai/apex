import { useKeyboard } from "@opentui/react";
import { useCallback, useState } from "react";
import { LANCE_DESCRIPTION } from "../../../core/agents/lance";
import type { FindingPolicy } from "../../../core/agents/offSecAgent";
import { useConfig } from "../../context/config";
import { Dialog } from "../../context/dialog";
import { useDimensions } from "../../context/dimensions";
import { useTheme } from "../../theme";
import DialogLayout from "../dialog-layout";

const MODES = [
  {
    value: "standard",
    label: "Standard",
    description: "Full Apex assessment workflow.",
  },
  {
    value: "strike",
    label: "Strike",
    description: "Focused research; no auto-discovery or agent fan-out.",
  },
  { value: "lance", label: "Lance", description: LANCE_DESCRIPTION },
] as const;
type ExecutionMode = (typeof MODES)[number]["value"];
type FocusedSetting = "mode" | "judge" | "save";
const FINDING_POLICIES: { value: FindingPolicy; label: string }[] = [
  { value: "native", label: "Enabled (Apex judge)" },
  { value: "external", label: "Disabled" },
];

interface AdvancedSettingsProps {
  onClose: () => void;
}

export default function AdvancedSettings({ onClose }: AdvancedSettingsProps) {
  const { colors } = useTheme();
  const dimensions = useDimensions();
  const compact = dimensions.width < 65 || dimensions.height < 24;
  const config = useConfig();
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [draftMode, setDraftMode] = useState<ExecutionMode>(
    config.data.lanceMode
      ? "lance"
      : config.data.strikeMode
        ? "strike"
        : "standard",
  );
  const [draftFindingPolicy, setDraftFindingPolicy] = useState<FindingPolicy>(
    config.data.findingPolicy ?? "native",
  );
  const [openSelect, setOpenSelect] = useState<"mode" | "judge" | null>(null);
  const [highlightedIndex, setHighlightedIndex] = useState(0);
  const [focusedSetting, setFocusedSetting] = useState<FocusedSetting>("mode");
  const selectedMode = MODES.find((mode) => mode.value === draftMode)!;
  const judgeAvailable = draftMode !== "standard";
  const choices = openSelect === "mode" ? MODES : FINDING_POLICIES;

  const toggleFocused = () => {
    if (focusedSetting === "mode") {
      setDraftMode(
        MODES[
          (MODES.findIndex((mode) => mode.value === draftMode) + 1) %
            MODES.length
        ]!.value,
      );
    } else if (focusedSetting === "judge") {
      setDraftFindingPolicy((policy) =>
        policy === "native" ? "external" : "native",
      );
    }
    setOpenSelect(null);
  };
  const openChoices = (setting: "mode" | "judge") => {
    setFocusedSetting(setting);
    setHighlightedIndex(
      setting === "mode"
        ? MODES.findIndex((mode) => mode.value === draftMode)
        : FINDING_POLICIES.findIndex(
            (policy) => policy.value === draftFindingPolicy,
          ),
    );
    setOpenSelect(setting);
  };
  const selectChoice = (index: number) => {
    if (openSelect === "mode") setDraftMode(MODES[index]!.value);
    else setDraftFindingPolicy(FINDING_POLICIES[index]!.value);
    setOpenSelect(null);
  };
  const moveFocus = (direction: number) => {
    const settings: FocusedSetting[] = judgeAvailable
      ? ["mode", "judge", "save"]
      : ["mode", "save"];
    setFocusedSetting(
      (focused) =>
        settings[
          (settings.indexOf(focused) + direction + settings.length) %
            settings.length
        ]!,
    );
  };
  const saveSettings = useCallback(async () => {
    if (saving) return;
    setSaving(true);
    setError(null);
    try {
      await config.update({
        strikeMode: draftMode === "strike",
        lanceMode: draftMode === "lance",
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
  }, [config, draftMode, draftFindingPolicy, onClose, saving]);

  useKeyboard((key) => {
    if (key.name === "tab") {
      key.preventDefault();
      toggleFocused();
      return;
    }
    if (openSelect) {
      key.preventDefault();
      if (key.name === "escape") setOpenSelect(null);
      else if (key.name === "up" || key.name === "down") {
        const direction = key.name === "up" ? -1 : 1;
        setHighlightedIndex(
          (index) => (index + direction + choices.length) % choices.length,
        );
      } else if (key.name === "return") selectChoice(highlightedIndex);
      return;
    }
    if (key.name === "escape") {
      key.preventDefault();
      onClose();
    } else if (key.name === "up" || key.name === "down") {
      key.preventDefault();
      moveFocus(key.name === "up" ? -1 : 1);
    } else if (key.name === "return") {
      key.preventDefault();
      if (focusedSetting === "save") void saveSettings();
      else openChoices(focusedSetting);
    }
  });

  const choiceList = (setting: "mode" | "judge") =>
    openSelect === setting && (
      <box flexDirection="column" overflow="hidden">
        {choices.map((choice, index) => (
          <box
            key={choice.value}
            flexDirection="row"
            paddingLeft={1}
            overflow="hidden"
            backgroundColor={
              index === highlightedIndex ? colors.backgroundSelected : undefined
            }
            onMouseDown={() => selectChoice(index)}
          >
            <text
              fg={index === highlightedIndex ? colors.primary : colors.text}
            >
              {index === highlightedIndex ? "❯ " : "  "}
              {choice.label}
            </text>
          </box>
        ))}
      </box>
    );

  return (
    <Dialog size="medium" onClose={onClose}>
      <DialogLayout
        title="Advanced Settings"
        escLabel={openSelect ? "back" : "close"}
        footerActions={[
          {
            key: "Enter",
            label: openSelect ? "Select" : "Activate",
            variant: "primary",
          },
          { key: "↑/↓", label: openSelect ? "Choose" : "Navigate" },
          ...(dimensions.width >= 60 && focusedSetting !== "save"
            ? [{ key: "Tab", label: "Toggle" }]
            : []),
        ]}
      >
        <box flexDirection="column" gap={compact ? 0 : 1} overflow="hidden">
          <box
            flexDirection="row"
            justifyContent="space-between"
            overflow="hidden"
            backgroundColor={
              focusedSetting === "mode" && !openSelect
                ? colors.backgroundSelected
                : undefined
            }
            onMouseDown={() => openChoices("mode")}
          >
            <text fg={focusedSetting === "mode" ? colors.primary : colors.text}>
              {focusedSetting === "mode" ? "❯ " : "  "}Mode
            </text>
            <text fg={colors.primary}>{selectedMode.label} ▾</text>
          </box>
          {choiceList("mode")}
          {(!compact || !openSelect) && (
            <text fg={colors.textMuted}>{selectedMode.description}</text>
          )}
          {judgeAvailable && (
            <>
              <box
                flexDirection="row"
                justifyContent="space-between"
                overflow="hidden"
                backgroundColor={
                  focusedSetting === "judge" && !openSelect
                    ? colors.backgroundSelected
                    : undefined
                }
                onMouseDown={() => openChoices("judge")}
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
                  {draftFindingPolicy === "native" ? "Apex judge" : "Disabled"}{" "}
                  ▾
                </text>
              </box>
              {choiceList("judge")}
              {!compact && (
                <text fg={colors.textMuted}>
                  When enabled, Apex's separate judge verifies submitted
                  evidence.
                </text>
              )}
            </>
          )}
          {!openSelect && (
            <text fg={colors.textMuted}>
              New sessions only.
              {draftMode === "lance" ? " Lance has a 15-minute budget." : ""}
            </text>
          )}
          <box
            flexDirection="row"
            overflow="hidden"
            backgroundColor={
              focusedSetting === "save" && !openSelect
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
