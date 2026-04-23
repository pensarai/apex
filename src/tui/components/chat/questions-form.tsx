import { useState, useMemo } from "react";
import { useKeyboard } from "@opentui/react";
import { useTheme } from "../../theme";
import { useDialog } from "../../context/dialog";
import { useDimensions } from "../../context/dimensions";
import { DialogControls } from "../shared/dialog-controls";
import type { ControlItem } from "../shared/dialog-controls";
import type {
  AskUserQuestion,
  AskUserQuestionAnswer,
} from "../../../core/agents/offSecAgent/tools/askUserQuestions";

const FOOTER_CONTROLS: ControlItem[] = [
  { key: "Enter", label: "to select", variant: "primary" },
  { key: "Tab/Arrow keys", label: "to navigate" },
  { key: "Esc", label: "to cancel" },
];

const MIN_CONTENT_HEIGHT = 10;

// Schema is deliberately permissive (see askUserQuestions.ts comment).
function normalizeQuestion(q: AskUserQuestion, index: number): AskUserQuestion {
  const fallbackHeader = `Q${index + 1}`;
  const trimmedHeader = (q.header ?? "").trim();
  const header =
    trimmedHeader.length === 0
      ? fallbackHeader
      : trimmedHeader.length > 20
        ? trimmedHeader.slice(0, 19) + "…"
        : trimmedHeader;

  const options = (q.options ?? []).slice(0, 4);

  return {
    ...q,
    header,
    multiSelect: q.multiSelect ?? false,
    allowFreeform: q.allowFreeform ?? true,
    options,
  };
}

interface QuestionsFormProps {
  questions: AskUserQuestion[];
  onSubmit: (answers: AskUserQuestionAnswer[]) => void;
  onSkip: () => void;
}

interface QuestionState {
  selected: Set<string>;
  freeformText: string;
  focusedIndex: number;
}

function initialState(questions: AskUserQuestion[]): QuestionState[] {
  return questions.map(() => ({
    selected: new Set<string>(),
    freeformText: "",
    focusedIndex: 0,
  }));
}

function isAnswered(state: QuestionState): boolean {
  if (state.selected.size > 0) return true;
  if (state.freeformText.trim().length > 0) return true;
  return false;
}

function tabIcon(question: AskUserQuestion, state: QuestionState): string {
  if (isAnswered(state)) return "✓";
  return question.multiSelect ? "⊠" : "□";
}

type RowKind =
  | { kind: "option"; optionIndex: number }
  | { kind: "freeform" }
  | { kind: "next" };

function buildRows(question: AskUserQuestion): RowKind[] {
  const rows: RowKind[] = question.options.map((_, optionIndex) => ({
    kind: "option",
    optionIndex,
  }));
  if (question.allowFreeform) rows.push({ kind: "freeform" });
  if (question.multiSelect) rows.push({ kind: "next" });
  return rows;
}

function buildAnswers(
  questions: AskUserQuestion[],
  states: QuestionState[],
): AskUserQuestionAnswer[] {
  return questions.map((q, i) => {
    const s = states[i]!;
    return {
      questionId: q.id,
      selectedOptionIds: Array.from(s.selected),
      freeformText: s.freeformText.trim().length > 0 ? s.freeformText : null,
    };
  });
}

// Compute how many chars a rendered tab occupies: " icon header " + gap
function tabWidth(header: string): number {
  // "icon " (2) + header + paddingLeft(1) + paddingRight(1) + gap(1)
  return header.length + 5;
}

export function QuestionsForm({
  questions: rawQuestions,
  onSubmit,
  onSkip,
}: QuestionsFormProps) {
  const { colors } = useTheme();
  const { width: termWidth } = useDimensions();
  // useKeyboard fires globally; gate it when a dialog is above us.
  const { stack, externalDialogOpen } = useDialog();
  const dialogOpen = stack.length > 0 || externalDialogOpen;

  const questions = useMemo(
    () => rawQuestions.map(normalizeQuestion),
    [rawQuestions],
  );

  const [states, setStates] = useState<QuestionState[]>(() =>
    initialState(questions),
  );
  const [activeTabIndex, setActiveTabIndex] = useState(0);
  const [submitFocusedIndex, setSubmitFocusedIndex] = useState(0);
  const [editingFreeform, setEditingFreeform] = useState(false);

  const submitTabIndex = questions.length;
  const onSubmitTab = activeTabIndex === submitTabIndex;

  const allAnswered = useMemo(() => states.every(isAnswered), [states]);

  const activeQuestion = onSubmitTab
    ? null
    : (questions[activeTabIndex] ?? null);
  const activeState = onSubmitTab ? null : states[activeTabIndex]!;
  const rows = useMemo<RowKind[]>(
    () => (activeQuestion ? buildRows(activeQuestion) : []),
    [activeQuestion],
  );
  const focusedRow =
    !onSubmitTab && activeState
      ? (rows[Math.min(activeState.focusedIndex, rows.length - 1)] ?? null)
      : null;

  const isFreeformFocused = !onSubmitTab && focusedRow?.kind === "freeform";

  const updateState = (index: number, patch: Partial<QuestionState>) => {
    setStates((prev) => {
      const next = [...prev];
      next[index] = { ...next[index]!, ...patch };
      return next;
    });
  };

  const setFocused = (questionIndex: number, focusedIndex: number) => {
    updateState(questionIndex, { focusedIndex });
  };

  const toggleOption = (questionIndex: number, optionIndex: number) => {
    const q = questions[questionIndex]!;
    const opt = q.options[optionIndex]!;
    setStates((prev) => {
      const next = [...prev];
      const cur = next[questionIndex]!;
      const nextSelected = new Set(cur.selected);
      if (q.multiSelect) {
        if (nextSelected.has(opt.id)) nextSelected.delete(opt.id);
        else nextSelected.add(opt.id);
      } else {
        nextSelected.clear();
        nextSelected.add(opt.id);
      }
      // For single-select, clear freeform text to maintain mutual exclusivity
      // (updateFreeformText already clears selected when freeform is typed).
      next[questionIndex] = q.multiSelect
        ? { ...cur, selected: nextSelected }
        : { ...cur, selected: nextSelected, freeformText: "" };
      return next;
    });
  };

  const updateFreeformText = (questionIndex: number, text: string) => {
    setStates((prev) => {
      const next = [...prev];
      const cur = next[questionIndex]!;
      const q = questions[questionIndex]!;
      if (q.multiSelect) {
        next[questionIndex] = { ...cur, freeformText: text };
      } else {
        next[questionIndex] = {
          ...cur,
          freeformText: text,
          selected: text.trim().length > 0 ? new Set<string>() : cur.selected,
        };
      }
      return next;
    });
  };

  const goToTab = (next: number) => {
    const clamped = Math.max(0, Math.min(submitTabIndex, next));
    if (clamped === activeTabIndex) return;
    setActiveTabIndex(clamped);
    setEditingFreeform(false);
    if (clamped === submitTabIndex) setSubmitFocusedIndex(0);
  };

  const advanceTab = () => goToTab(activeTabIndex + 1);
  const retreatTab = () => goToTab(activeTabIndex - 1);

  const moveRow = (delta: number) => {
    if (!activeState) return;
    const max = Math.max(0, rows.length - 1);
    const next = Math.max(0, Math.min(max, activeState.focusedIndex + delta));
    setFocused(activeTabIndex, next);
  };

  const commitActiveRow = () => {
    if (onSubmitTab) {
      if (submitFocusedIndex === 0) {
        onSubmit(buildAnswers(questions, states));
      } else {
        goToTab(Math.max(0, submitTabIndex - 1));
      }
      return;
    }
    if (!activeQuestion || !activeState || !focusedRow) return;

    const q = activeQuestion;

    if (focusedRow.kind === "option") {
      toggleOption(activeTabIndex, focusedRow.optionIndex);
      if (!q.multiSelect) advanceTab();
      return;
    }

    if (focusedRow.kind === "freeform") {
      // Enter on freeform commits text and advances (single-select) or
      // just confirms (multi-select). Typing starts automatically on focus.
      setEditingFreeform(false);
      if (!q.multiSelect) advanceTab();
      return;
    }

    if (focusedRow.kind === "next") {
      advanceTab();
      return;
    }
  };

  const quickPick = (digit: number) => {
    if (onSubmitTab) {
      if (digit === 1) {
        setSubmitFocusedIndex(0);
        onSubmit(buildAnswers(questions, states));
      } else if (digit === 2) {
        setSubmitFocusedIndex(1);
        goToTab(Math.max(0, submitTabIndex - 1));
      }
      return;
    }
    if (!activeQuestion || !activeState) return;
    const q = activeQuestion;
    const idx = digit - 1;
    if (idx < q.options.length) {
      setFocused(activeTabIndex, idx);
      toggleOption(activeTabIndex, idx);
      if (!q.multiSelect) advanceTab();
      return;
    }
    if (q.allowFreeform && idx === q.options.length) {
      setFocused(activeTabIndex, idx);
      setEditingFreeform(true);
      return;
    }
  };

  useKeyboard((key) => {
    if (dialogOpen) return;

    // Freeform is auto-focused when its row is focused. Only intercept
    // keys that exit or navigate away; printable chars go to <input>.
    if (editingFreeform || isFreeformFocused) {
      if (key.name === "escape") {
        key.preventDefault?.();
        setEditingFreeform(false);
        // Move focus off the freeform row so the input loses focus.
        // When there are no option rows above (focusedIndex === 0), skip
        // instead — otherwise Esc is trapped on freeform-only questions.
        if (activeState && activeState.focusedIndex > 0) {
          moveRow(-1);
        } else {
          onSkip();
        }
        return;
      }
      if (key.name === "up") {
        key.preventDefault?.();
        setEditingFreeform(false);
        moveRow(-1);
        return;
      }
      if (key.name === "down") {
        key.preventDefault?.();
        setEditingFreeform(false);
        moveRow(1);
        return;
      }
      if (key.name === "return") {
        key.preventDefault?.();
        setEditingFreeform(false);
        if (activeQuestion && !activeQuestion.multiSelect) {
          advanceTab();
        }
        return;
      }
      if (key.name === "tab") {
        key.preventDefault?.();
        setEditingFreeform(false);
        if (key.shift) retreatTab();
        else advanceTab();
        return;
      }
      return;
    }

    if (key.name === "escape") {
      key.preventDefault?.();
      onSkip();
      return;
    }

    if (key.name === "tab") {
      key.preventDefault?.();
      if (key.shift) retreatTab();
      else advanceTab();
      return;
    }

    if (key.name === "left") {
      key.preventDefault?.();
      retreatTab();
      return;
    }
    if (key.name === "right") {
      key.preventDefault?.();
      advanceTab();
      return;
    }

    if (key.name === "up") {
      key.preventDefault?.();
      if (onSubmitTab) {
        setSubmitFocusedIndex((v) => Math.max(0, v - 1));
      } else {
        moveRow(-1);
      }
      return;
    }
    if (key.name === "down") {
      key.preventDefault?.();
      if (onSubmitTab) {
        setSubmitFocusedIndex((v) => Math.min(1, v + 1));
      } else {
        moveRow(1);
      }
      return;
    }

    if (key.name === "space") {
      key.preventDefault?.();
      if (onSubmitTab) return;
      if (!activeQuestion || !focusedRow) return;
      if (!activeQuestion.multiSelect) return;
      if (focusedRow.kind === "option") {
        toggleOption(activeTabIndex, focusedRow.optionIndex);
        return;
      }
      return;
    }

    if (key.name === "return") {
      key.preventDefault?.();
      commitActiveRow();
      return;
    }

    if (key.raw && /^[1-9]$/.test(key.raw)) {
      key.preventDefault?.();
      quickPick(parseInt(key.raw, 10));
      return;
    }
  });

  return (
    <box
      flexDirection="column"
      marginLeft={1}
      marginRight={1}
      paddingLeft={1}
      paddingRight={1}
      paddingTop={1}
      paddingBottom={1}
      border={true}
      borderColor={colors.primary}
      flexShrink={0}
      overflow="hidden"
    >
      <TabBar
        questions={questions}
        states={states}
        activeTabIndex={activeTabIndex}
        submitTabIndex={submitTabIndex}
        availableWidth={termWidth - 6}
      />

      <box
        flexDirection="column"
        marginTop={1}
        paddingLeft={1}
        minHeight={MIN_CONTENT_HEIGHT}
      >
        {onSubmitTab ? (
          <SubmitView
            allAnswered={allAnswered}
            focusedIndex={submitFocusedIndex}
          />
        ) : activeQuestion && activeState ? (
          <QuestionView
            question={activeQuestion}
            state={activeState}
            rows={rows}
            isFreeformFocused={isFreeformFocused}
            onFreeformInput={(v) => updateFreeformText(activeTabIndex, v)}
          />
        ) : null}
      </box>

      <box marginTop={1}>
        <DialogControls controls={FOOTER_CONTROLS} />
      </box>
    </box>
  );
}

function TabBar({
  questions,
  states,
  activeTabIndex,
  submitTabIndex,
  availableWidth,
}: {
  questions: AskUserQuestion[];
  states: QuestionState[];
  activeTabIndex: number;
  submitTabIndex: number;
  availableWidth: number;
}) {
  const { colors } = useTheme();

  // All tab items: question tabs + submit tab
  const allTabs = useMemo(() => {
    const tabs = questions.map((q, i) => ({
      index: i,
      header: q.header,
      width: tabWidth(q.header),
    }));
    tabs.push({
      index: submitTabIndex,
      header: "Submit",
      width: tabWidth("Submit"),
    });
    return tabs;
  }, [questions, submitTabIndex]);

  // Determine which tabs are visible on a single line.
  // Reserve space for arrows (2 chars each) + overflow indicators.
  const { visibleStart, visibleEnd, hiddenBefore, hiddenAfter } =
    useMemo(() => {
      const arrowSpace = 4; // "← " and " →"
      const budget = availableWidth - arrowSpace;

      // Always include the active tab; expand outward from there.
      let start = activeTabIndex;
      let end = activeTabIndex;
      let used = allTabs[activeTabIndex]?.width ?? 0;

      // Expand right, then left
      while (end + 1 < allTabs.length) {
        const next = allTabs[end + 1]!;
        // Reserve space for "+N" indicator if there are tabs past what we show
        const indicatorReserve = end + 2 < allTabs.length ? 5 : 0;
        if (used + next.width + indicatorReserve > budget) break;
        used += next.width;
        end++;
      }
      while (start - 1 >= 0) {
        const prev = allTabs[start - 1]!;
        const indicatorReserve = start - 2 >= 0 ? 5 : 0;
        if (used + prev.width + indicatorReserve > budget) break;
        used += prev.width;
        start--;
      }

      return {
        visibleStart: start,
        visibleEnd: end,
        hiddenBefore: start,
        hiddenAfter: allTabs.length - 1 - end,
      };
    }, [allTabs, activeTabIndex, availableWidth]);

  const leftActive = activeTabIndex > 0;
  const rightActive = activeTabIndex < submitTabIndex;

  return (
    <box flexDirection="row" gap={1} alignItems="center" overflow="hidden">
      <text fg={leftActive ? colors.text : colors.textMuted}>←</text>

      {hiddenBefore > 0 && (
        <text fg={colors.textMuted}>{`+${hiddenBefore}`}</text>
      )}

      {allTabs.slice(visibleStart, visibleEnd + 1).map((tab) => {
        const isSubmit = tab.index === submitTabIndex;
        const active = tab.index === activeTabIndex;
        const s = !isSubmit ? states[tab.index]! : null;
        const q = !isSubmit ? questions[tab.index]! : null;

        const icon = isSubmit ? "✓" : tabIcon(q!, s!);
        const iconFg = isSubmit
          ? colors.success
          : isAnswered(s!)
            ? colors.success
            : active
              ? colors.primary
              : colors.textMuted;
        const fg = active ? colors.text : colors.textMuted;

        return (
          <box
            key={isSubmit ? "submit" : q!.id}
            flexDirection="row"
            paddingLeft={1}
            paddingRight={1}
            backgroundColor={active ? colors.backgroundSelected : "transparent"}
          >
            <text>
              <span fg={iconFg}>{icon} </span>
              <span fg={fg}>{tab.header}</span>
            </text>
          </box>
        );
      })}

      {hiddenAfter > 0 && (
        <text fg={colors.textMuted}>{`+${hiddenAfter}`}</text>
      )}

      <text fg={rightActive ? colors.text : colors.textMuted}>→</text>
    </box>
  );
}

function QuestionView({
  question,
  state,
  rows,
  isFreeformFocused,
  onFreeformInput,
}: {
  question: AskUserQuestion;
  state: QuestionState;
  rows: RowKind[];
  isFreeformFocused: boolean;
  onFreeformInput: (value: string) => void;
}) {
  const { colors } = useTheme();
  const focusedIdx = Math.min(state.focusedIndex, rows.length - 1);

  return (
    <box flexDirection="column">
      <text fg={colors.text}>{question.question}</text>

      <box flexDirection="column" marginTop={1}>
        {rows.map((row, rowIdx) => {
          const focused = rowIdx === focusedIdx;
          return (
            <Row
              key={rowKey(row, rowIdx)}
              row={row}
              rowIndex={rowIdx}
              focused={focused}
              question={question}
              state={state}
              isFreeformFocused={isFreeformFocused && focused}
              onFreeformInput={onFreeformInput}
            />
          );
        })}
      </box>
    </box>
  );
}

function rowKey(row: RowKind, rowIdx: number): string {
  switch (row.kind) {
    case "option":
      return `option-${row.optionIndex}`;
    case "freeform":
      return `freeform-${rowIdx}`;
    case "next":
      return `next-${rowIdx}`;
  }
}

function Row({
  row,
  rowIndex,
  focused,
  question,
  state,
  isFreeformFocused,
  onFreeformInput,
}: {
  row: RowKind;
  rowIndex: number;
  focused: boolean;
  question: AskUserQuestion;
  state: QuestionState;
  isFreeformFocused: boolean;
  onFreeformInput: (value: string) => void;
}) {
  const { colors } = useTheme();
  const marker = focused ? ")" : " ";
  const markerColor = focused ? colors.primary : colors.textMuted;

  if (row.kind === "option") {
    const opt = question.options[row.optionIndex]!;
    const selected = state.selected.has(opt.id);
    const number = row.optionIndex + 1;
    const descColor = colors.textMuted;
    return (
      <box flexDirection="column">
        <box flexDirection="row">
          <text fg={markerColor}>{marker + " "}</text>
          <text>
            <span fg={colors.textMuted}>{`${number}. `}</span>
            {question.multiSelect ? (
              <span fg={selected ? colors.success : colors.textMuted}>
                {selected ? "[✓] " : "[ ] "}
              </span>
            ) : null}
            <span fg={colors.text}>{opt.label}</span>
          </text>
        </box>
        {opt.description ? (
          <box flexDirection="row">
            <text fg={descColor}>
              {"    " + (question.multiSelect ? "    " : "") + opt.description}
            </text>
          </box>
        ) : null}
      </box>
    );
  }

  if (row.kind === "freeform") {
    const number = rowIndex + 1;
    const hasText = state.freeformText.trim().length > 0;
    const prefix = question.multiSelect ? (hasText ? "[✓] " : "[ ] ") : "";
    const prefixColor = question.multiSelect
      ? hasText
        ? colors.success
        : colors.textMuted
      : colors.textMuted;
    return (
      <box flexDirection="row">
        <text fg={markerColor}>{marker + " "}</text>
        <text>
          <span fg={colors.textMuted}>{`${number}. `}</span>
          {question.multiSelect ? <span fg={prefixColor}>{prefix}</span> : null}
        </text>
        {isFreeformFocused ? (
          <input
            width="60%"
            value={state.freeformText}
            onInput={onFreeformInput}
            focused={true}
            placeholder="Type something…"
            textColor={colors.text}
            backgroundColor="transparent"
            cursorColor={colors.textMuted}
          />
        ) : hasText ? (
          <text fg={colors.text}>{state.freeformText}</text>
        ) : (
          <text fg={colors.textMuted}>Type something…</text>
        )}
      </box>
    );
  }

  return (
    <box flexDirection="row" marginTop={1}>
      <text fg={markerColor}>{marker + " "}</text>
      <text fg={focused ? colors.primary : colors.textMuted}>Next</text>
    </box>
  );
}

const SUBMIT_OPTIONS = ["Submit answers", "Cancel"] as const;

function SubmitView({
  allAnswered,
  focusedIndex,
}: {
  allAnswered: boolean;
  focusedIndex: number;
}) {
  const { colors } = useTheme();
  return (
    <box flexDirection="column">
      {!allAnswered ? (
        <box marginTop={1}>
          <text fg={colors.warning}>⚠ You have not answered all questions</text>
        </box>
      ) : null}
      <text fg={colors.text} marginTop={1}>
        Ready to submit your answers?
      </text>
      <box flexDirection="column" marginTop={1}>
        {SUBMIT_OPTIONS.map((label, i) => {
          const focused = i === focusedIndex;
          return (
            <box key={label} flexDirection="row">
              <text fg={focused ? colors.primary : colors.textMuted}>
                {focused ? ") " : "  "}
              </text>
              <text>
                <span fg={colors.textMuted}>{`${i + 1}. `}</span>
                <span fg={focused ? colors.text : colors.textMuted}>
                  {label}
                </span>
              </text>
            </box>
          );
        })}
      </box>
    </box>
  );
}

export default QuestionsForm;
