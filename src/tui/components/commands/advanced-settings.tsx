import { useKeyboard } from "@opentui/react";
import { useCallback, useState } from "react";
import { LANCE_DESCRIPTION } from "../../../core/agents/lance";
import {
  DEFAULT_LANCE_BUDGET,
  type LanceBudget,
  lanceBudgetSchema,
} from "../../../core/agents/lanceBudget";
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
  {
    value: "default-v2",
    label: "Default v2",
    description:
      "Experimental adaptive operator for research and everyday work.",
  },
] as const;
type ExecutionMode = (typeof MODES)[number]["value"];
type SelectSetting = "mode" | "judge" | "budget";
type FocusedSetting = SelectSetting | "limit" | "save";
const BUDGETS = [
  { value: "steps", label: "Steps", initial: 200 },
  { value: "tokens", label: "Tokens", initial: 1000000 },
  { value: "time", label: "Time", initial: 900 },
] as const;
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
      : config.data.defaultV2Mode
        ? "default-v2"
        : config.data.strikeMode
          ? "strike"
          : "standard",
  );
  const [draftFindingPolicy, setDraftFindingPolicy] = useState<FindingPolicy>(
    config.data.findingPolicy ?? "native",
  );
  const savedBudget = config.data.lanceBudget ?? DEFAULT_LANCE_BUDGET;
  const [budgetKind, setBudgetKind] = useState<LanceBudget["kind"]>(
    savedBudget.kind,
  );
  const [budgetLimit, setBudgetLimit] = useState(
    String(
      savedBudget.kind === "time"
        ? savedBudget.limit / 1000
        : savedBudget.limit,
    ),
  );
  const chooseBudget = (index: number) => {
    const choice = BUDGETS[index]!;
    if (choice.value !== budgetKind) setBudgetLimit(String(choice.initial));
    setBudgetKind(choice.value);
  };
  const [openSelect, setOpenSelect] = useState<SelectSetting | null>(null);
  const [highlightedIndex, setHighlightedIndex] = useState(0);
  const [focusedSetting, setFocusedSetting] = useState<FocusedSetting>("mode");
  const selectedMode = MODES.find((mode) => mode.value === draftMode)!;
  const judgeAvailable = draftMode !== "standard";
  const choices =
    openSelect === "mode"
      ? MODES
      : openSelect === "budget"
        ? BUDGETS
        : FINDING_POLICIES;

  const toggleFocused = () => {
    if (focusedSetting === "mode") {
      setDraftMode(
        MODES[
          (MODES.findIndex((mode) => mode.value === draftMode) + 1) %
            MODES.length
        ]!.value,
      );
    } else if (focusedSetting === "budget") {
      chooseBudget(
        (BUDGETS.findIndex((b) => b.value === budgetKind) + 1) % BUDGETS.length,
      );
    } else if (focusedSetting === "limit") {
      setFocusedSetting("save");
    } else if (focusedSetting === "judge") {
      setDraftFindingPolicy((policy) =>
        policy === "native" ? "external" : "native",
      );
    }
    setOpenSelect(null);
  };
  const openChoices = (setting: SelectSetting) => {
    setFocusedSetting(setting);
    setHighlightedIndex(
      setting === "mode"
        ? MODES.findIndex((mode) => mode.value === draftMode)
        : setting === "budget"
          ? BUDGETS.findIndex((b) => b.value === budgetKind)
          : FINDING_POLICIES.findIndex(
              (policy) => policy.value === draftFindingPolicy,
            ),
    );
    setOpenSelect(setting);
  };
  const selectChoice = (index: number) => {
    if (openSelect === "mode") setDraftMode(MODES[index]!.value);
    else if (openSelect === "budget") chooseBudget(index);
    else setDraftFindingPolicy(FINDING_POLICIES[index]!.value);
    setOpenSelect(null);
  };
  const moveFocus = (direction: number) => {
    const settings: FocusedSetting[] = judgeAvailable
      ? draftMode === "lance"
        ? ["mode", "judge", "budget", "limit", "save"]
        : ["mode", "judge", "save"]
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
      const parsedBudget = lanceBudgetSchema.safeParse({
        kind: budgetKind,
        limit:
          budgetKind === "time"
            ? Math.round(Number(budgetLimit) * 1000)
            : Number(budgetLimit),
      });
      if (draftMode === "lance" && !parsedBudget.success) {
        setError(
          budgetKind === "time"
            ? "Enter a duration from 0.002 to 2147483.647 seconds."
            : "Enter a positive whole-number limit.",
        );
        setSaving(false);
        return;
      }
      const budget =
        draftMode === "lance" && parsedBudget.success
          ? parsedBudget.data
          : undefined;
      await config.update({
        strikeMode: draftMode === "strike",
        lanceMode: draftMode === "lance",
        defaultV2Mode: draftMode === "default-v2",
        findingPolicy: draftFindingPolicy,
        ...(budget ? { lanceBudget: budget } : {}),
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
  }, [
    config,
    draftMode,
    draftFindingPolicy,
    budgetKind,
    budgetLimit,
    onClose,
    saving,
  ]);

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
      else if (focusedSetting === "limit") setFocusedSetting("save");
      else openChoices(focusedSetting);
    }
  });

  const choiceList = (setting: SelectSetting) =>
    openSelect === setting && (
      <box flexDirection="column" overflow="hidden">
        {choices.map((choice, index) => (
          <box
            key={choice.value}
            flexDirection="row"
            flexShrink={0}
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
        <box
          flexDirection="column"
          gap={compact || draftMode === "lance" ? 0 : 1}
          overflow="hidden"
        >
          <box
            flexDirection="row"
            flexShrink={0}
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
            <text fg={colors.textMuted}>
              {compact && draftMode === "lance"
                ? "Minimal offensive-capability mode."
                : selectedMode.description}
            </text>
          )}
          {judgeAvailable && (
            <>
              <box
                flexDirection="row"
                flexShrink={0}
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
          {draftMode === "lance" && (
            <>
              <box
                flexDirection="row"
                flexShrink={0}
                justifyContent="space-between"
                overflow="hidden"
                backgroundColor={
                  focusedSetting === "budget"
                    ? colors.backgroundSelected
                    : undefined
                }
                onMouseDown={() => openChoices("budget")}
              >
                <text
                  fg={
                    focusedSetting === "budget" ? colors.primary : colors.text
                  }
                >
                  {focusedSetting === "budget" ? "❯ " : "  "}Run budget
                </text>
                <text fg={colors.primary}>
                  {BUDGETS.find((b) => b.value === budgetKind)!.label} ▾
                </text>
              </box>
              {choiceList("budget")}
              <box
                flexDirection="row"
                flexShrink={0}
                justifyContent="space-between"
                overflow="hidden"
                onMouseDown={() => {
                  setOpenSelect(null);
                  setFocusedSetting("limit");
                }}
              >
                <text
                  fg={focusedSetting === "limit" ? colors.primary : colors.text}
                >
                  {focusedSetting === "limit" ? "❯ " : "  "}Limit (
                  {budgetKind === "time" ? "seconds" : budgetKind})
                </text>
                {/* Reserve the cursor cell and OpenTUI's minimum scroll margin. */}
                <input
                  width={Math.min(18, budgetLimit.length + 2)}
                  scrollMargin={0}
                  value={budgetLimit}
                  onInput={setBudgetLimit}
                  focused={focusedSetting === "limit" && !openSelect}
                  textColor={colors.text}
                  focusedTextColor={colors.text}
                  backgroundColor={colors.backgroundElement}
                  focusedBackgroundColor={colors.backgroundSelected}
                />
              </box>
              {!compact && !openSelect && (
                <text fg={colors.textMuted}>
                  {budgetKind === "tokens"
                    ? "Input + output, including cache, compaction and judge. Checked after requests."
                    : "One budget per turn. Other budget types are disabled."}
                </text>
              )}
            </>
          )}
          {!openSelect && <text fg={colors.textMuted}>New sessions only.</text>}
          <box
            flexDirection="row"
            flexShrink={0}
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
