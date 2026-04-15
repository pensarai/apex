/**
 * Tab-based UI for the agent's `ask_user_questions` tool.
 *
 * Freeform-edit mode: the underlying `<input>` owns arrow keys for cursor
 * movement. ↑/↓/Esc exit edit mode; Enter commits (single-select advances,
 * multi-select toggles).
 */

import { useState, useMemo } from "react";
import { useKeyboard } from "@opentui/react";
import { useTheme } from "../../theme";
import { useDialog } from "../../context/dialog";
import { DialogControls } from "../shared/dialog-controls";
import type {
  AskUserQuestion,
  AskUserQuestionAnswer,
} from "../../../core/agents/offSecAgent/tools/askUserQuestions";

// The AskUserQuestionSchema is permissive (see askUserQuestions.ts);
// normalize defensively so the UI never has to handle missing fields.
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

// focusedIndex layout: 0..N-1 = option rows, N = freeform row (if
// allowFreeform), last = "Next" row (multi-select only).
interface QuestionState {
  selected: Set<string>;
  freeformText: string;
  freeformSelected: boolean;
  focusedIndex: number;
}

function initialState(questions: AskUserQuestion[]): QuestionState[] {
  return questions.map(() => ({
    selected: new Set<string>(),
    freeformText: "",
    freeformSelected: false,
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

export function QuestionsForm({
  questions: rawQuestions,
  onSubmit,
  onSkip,
}: QuestionsFormProps) {
  const { colors } = useTheme();
  // Gate keyboard handling when another dialog is mounted above us —
  // opentui's useKeyboard fires globally, so without this the form
  // would steal keys from whatever is on top.
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

  // Only meaningful when !onSubmitTab.
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

  // ── State mutators ─────────────────────────────────────────────────

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
      next[questionIndex] = { ...cur, selected: nextSelected };
      return next;
    });
  };

  const updateFreeformText = (questionIndex: number, text: string) => {
    setStates((prev) => {
      const next = [...prev];
      const cur = next[questionIndex]!;
      const q = questions[questionIndex]!;
      if (q.multiSelect) {
        next[questionIndex] = {
          ...cur,
          freeformText: text,
          freeformSelected: text.trim().length > 0,
        };
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

  // ── Tab + row navigation ───────────────────────────────────────────

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

  // ── Actions on Enter ───────────────────────────────────────────────

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
      setEditingFreeform(true);
      return;
    }

    if (focusedRow.kind === "next") {
      advanceTab();
      return;
    }
  };

  // ── Quick-pick 1..9 ────────────────────────────────────────────────

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
      setStates((prev) => {
        const next = [...prev];
        const cur = next[activeTabIndex]!;
        next[activeTabIndex] = { ...cur, focusedIndex: idx };
        return next;
      });
      toggleOption(activeTabIndex, idx);
      if (!q.multiSelect) advanceTab();
      return;
    }
    if (q.allowFreeform && idx === q.options.length) {
      setStates((prev) => {
        const next = [...prev];
        const cur = next[activeTabIndex]!;
        next[activeTabIndex] = { ...cur, focusedIndex: idx };
        return next;
      });
      setEditingFreeform(true);
      return;
    }
  };

  // ── Keyboard handling ──────────────────────────────────────────────

  useKeyboard((key) => {
    if (dialogOpen) return;

    // Freeform-edit mode: the <input> owns printable chars + left/right;
    // only intercept mode-exit keys here.
    if (editingFreeform) {
      if (key.name === "escape") {
        key.preventDefault?.();
        setEditingFreeform(false);
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
      if (focusedRow.kind === "freeform") {
        setEditingFreeform(true);
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

  // ── Render ─────────────────────────────────────────────────────────

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
      // Fixed-bottom dialog: flexShrink={0} prevents the parent flex
      // layout from squashing us; overflow="hidden" stops content from
      // bleeding into adjacent UI (see AGENTS.md "Terminal size resilience").
      flexShrink={0}
      overflow="hidden"
    >
      {/* Tab bar */}
      <TabBar
        questions={questions}
        states={states}
        activeTabIndex={activeTabIndex}
        submitTabIndex={submitTabIndex}
      />

      {/* Content panel */}
      <box flexDirection="column" marginTop={1} paddingLeft={1}>
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
            editingFreeform={editingFreeform}
            onFreeformInput={(v) => updateFreeformText(activeTabIndex, v)}
          />
        ) : null}
      </box>

      {/* Footer key hint */}
      <box flexDirection="row" marginTop={1}>
        <DialogControls
          controls={[
            { key: "Enter", label: "to select", variant: "primary" },
            { key: "Tab/Arrow keys", label: "to navigate" },
            { key: "Esc", label: "to cancel" },
          ]}
        />
      </box>
    </box>
  );
}

// ─── Tab bar ────────────────────────────────────────────────────────

function TabBar({
  questions,
  states,
  activeTabIndex,
  submitTabIndex,
}: {
  questions: AskUserQuestion[];
  states: QuestionState[];
  activeTabIndex: number;
  submitTabIndex: number;
}) {
  const { colors } = useTheme();
  const leftActive = activeTabIndex > 0;
  const rightActive = activeTabIndex < submitTabIndex;

  return (
    <box flexDirection="row" gap={1} alignItems="center">
      {/* Left chevron */}
      <text fg={leftActive ? colors.text : colors.textMuted}>←</text>

      {/* Question tabs */}
      {questions.map((q, i) => {
        const active = i === activeTabIndex;
        const s = states[i]!;
        const icon = tabIcon(q, s);
        const label = q.header;
        const fg = active ? colors.text : colors.textMuted;
        const iconFg = isAnswered(s)
          ? colors.success
          : active
            ? colors.primary
            : colors.textMuted;
        return (
          <box
            key={q.id}
            flexDirection="row"
            paddingLeft={1}
            paddingRight={1}
            backgroundColor={active ? colors.backgroundSelected : "transparent"}
          >
            <text>
              <span fg={iconFg}>{icon} </span>
              <span fg={fg}>{label}</span>
            </text>
          </box>
        );
      })}

      {/* Submit tab */}
      <box
        flexDirection="row"
        paddingLeft={1}
        paddingRight={1}
        backgroundColor={
          activeTabIndex === submitTabIndex
            ? colors.backgroundSelected
            : "transparent"
        }
      >
        <text>
          <span fg={colors.success}>✓ </span>
          <span
            fg={
              activeTabIndex === submitTabIndex ? colors.text : colors.textMuted
            }
          >
            Submit
          </span>
        </text>
      </box>

      {/* Right chevron */}
      <text fg={rightActive ? colors.text : colors.textMuted}>→</text>
    </box>
  );
}

// ─── Question view (single tab body) ────────────────────────────────

function QuestionView({
  question,
  state,
  rows,
  editingFreeform,
  onFreeformInput,
}: {
  question: AskUserQuestion;
  state: QuestionState;
  rows: RowKind[];
  editingFreeform: boolean;
  onFreeformInput: (value: string) => void;
}) {
  const { colors } = useTheme();
  const focusedIdx = Math.min(state.focusedIndex, rows.length - 1);

  return (
    <box flexDirection="column">
      {/* Question text */}
      <text fg={colors.text}>{question.question}</text>
      <box height={1} />

      {/* Rows */}
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
            editingFreeform={editingFreeform}
            onFreeformInput={onFreeformInput}
          />
        );
      })}
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
  editingFreeform,
  onFreeformInput,
}: {
  row: RowKind;
  rowIndex: number;
  focused: boolean;
  question: AskUserQuestion;
  state: QuestionState;
  editingFreeform: boolean;
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
    const prefix = question.multiSelect
      ? state.freeformSelected || hasText
        ? "[✓] "
        : "[ ] "
      : "";
    const prefixColor = question.multiSelect
      ? state.freeformSelected || hasText
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
        {focused && editingFreeform ? (
          <input
            width="60%"
            value={state.freeformText}
            onInput={onFreeformInput}
            focused={true}
            placeholder="Type something."
            textColor={colors.text}
            backgroundColor="transparent"
            cursorColor={colors.textMuted}
          />
        ) : hasText ? (
          <text fg={colors.text}>{state.freeformText}</text>
        ) : (
          <text fg={colors.textMuted}>Type something.</text>
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

// ─── Submit view ────────────────────────────────────────────────────

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
      <text fg={colors.text}>Review your answers</text>
      {!allAnswered ? (
        <box marginTop={1}>
          <text fg={colors.warning}>⚠ You have not answered all questions</text>
        </box>
      ) : null}
      <box height={1} />
      <text fg={colors.text}>Ready to submit your answers?</text>
      <box height={1} />
      <box flexDirection="row">
        <text fg={focusedIndex === 0 ? colors.primary : colors.textMuted}>
          {focusedIndex === 0 ? ") " : "  "}
        </text>
        <text>
          <span fg={colors.textMuted}>{"1. "}</span>
          <span fg={focusedIndex === 0 ? colors.text : colors.textMuted}>
            Submit answers
          </span>
        </text>
      </box>
      <box flexDirection="row">
        <text fg={focusedIndex === 1 ? colors.primary : colors.textMuted}>
          {focusedIndex === 1 ? ") " : "  "}
        </text>
        <text>
          <span fg={colors.textMuted}>{"2. "}</span>
          <span fg={focusedIndex === 1 ? colors.text : colors.textMuted}>
            Cancel
          </span>
        </text>
      </box>
    </box>
  );
}

export default QuestionsForm;
