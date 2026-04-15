/**
 * Questions Form
 *
 * Renders a batch of grounded multi-choice questions emitted by the
 * agent's `ask_user_questions` tool. Pauses the operator dashboard
 * until the user submits answers (or skips), at which point the
 * tool-result is appended to the conversation and the agent resumes.
 *
 * Keybinding conventions (chosen to avoid clashes with the inline
 * approval prompt, which uses Y/A/N):
 *
 * - Tab / Shift+Tab — move focus between questions
 * - ↑ / ↓           — move within the focused question's option list (and
 *                     to/from the freeform "Other" row when allowed)
 * - Space           — select / toggle the focused option
 * - Enter           — single-select: select; multi-select: same as Space;
 *                     when all questions are answered: submit
 * - 1-9             — quick-select option N for the focused question
 * - S               — skip (only when focused outside the freeform input)
 * - Esc             — also triggers skip
 */

import { useState, useMemo } from "react";
import { useKeyboard } from "@opentui/react";
import { useTheme } from "../../theme";
import { DialogControls } from "../shared/dialog-controls";
import type {
  AskUserQuestion,
  AskUserQuestionAnswer,
} from "../../../core/agents/offSecAgent/tools/askUserQuestions";

interface QuestionsFormProps {
  questions: AskUserQuestion[];
  onSubmit: (answers: AskUserQuestionAnswer[]) => void;
  onSkip: () => void;
}

/**
 * Per-question selection state.
 * - `selected` holds the chosen option IDs (single- or multi-select).
 * - `freeformText` holds the freeform answer when the "Other" row is in use.
 * - `freeformActive` is true when the user explicitly enabled the freeform
 *   row for this question (so an empty freeform string still counts as
 *   "in use" while the user is typing).
 */
interface QuestionState {
  selected: Set<string>;
  freeformText: string;
  freeformActive: boolean;
}

function initialState(questions: AskUserQuestion[]): QuestionState[] {
  return questions.map(() => ({
    selected: new Set<string>(),
    freeformText: "",
    freeformActive: false,
  }));
}

function isAnswered(state: QuestionState): boolean {
  if (state.selected.size > 0) return true;
  if (state.freeformActive && state.freeformText.trim().length > 0) return true;
  return false;
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
      freeformText:
        s.freeformActive && s.freeformText.trim().length > 0
          ? s.freeformText
          : null,
    };
  });
}

export function QuestionsForm({
  questions,
  onSubmit,
  onSkip,
}: QuestionsFormProps) {
  const { colors } = useTheme();

  const [states, setStates] = useState<QuestionState[]>(() =>
    initialState(questions),
  );
  const [questionFocus, setQuestionFocus] = useState(0);
  // optionFocus: 0..options.length-1 = an option row;
  // options.length = the freeform "Other" row (when allowed)
  const [optionFocus, setOptionFocus] = useState(0);

  const allAnswered = useMemo(() => states.every(isAnswered), [states]);

  const focusedQuestion = questions[questionFocus]!;
  const optionCount = focusedQuestion.options.length;
  const isOnFreeformRow =
    focusedQuestion.allowFreeform && optionFocus === optionCount;

  const focusOption = (idx: number) => {
    const max =
      focusedQuestion.options.length -
      1 +
      (focusedQuestion.allowFreeform ? 1 : 0);
    setOptionFocus(Math.max(0, Math.min(idx, max)));
  };

  const moveQuestion = (delta: number) => {
    const next = Math.max(
      0,
      Math.min(questions.length - 1, questionFocus + delta),
    );
    if (next !== questionFocus) {
      setQuestionFocus(next);
      setOptionFocus(0);
    }
  };

  const toggleOption = (qIdx: number, optionId: string) => {
    setStates((prev) => {
      const updated = [...prev];
      const cur = updated[qIdx]!;
      const next = new Set(cur.selected);
      const isMulti = questions[qIdx]!.multiSelect;
      if (isMulti) {
        if (next.has(optionId)) next.delete(optionId);
        else next.add(optionId);
      } else {
        next.clear();
        next.add(optionId);
      }
      // Selecting an option clears the freeform-active flag for clarity
      // (single-select especially: pick from list OR write freeform, not both).
      // For multi-select, leave freeform alone — the user may want both.
      const freeformActive = isMulti ? cur.freeformActive : false;
      updated[qIdx] = {
        ...cur,
        selected: next,
        freeformActive,
        freeformText: freeformActive ? cur.freeformText : "",
      };
      return updated;
    });
  };

  const enterFreeform = (qIdx: number) => {
    setStates((prev) => {
      const updated = [...prev];
      const cur = updated[qIdx]!;
      // For single-select, clear the picked option when activating freeform.
      const isMulti = questions[qIdx]!.multiSelect;
      updated[qIdx] = {
        ...cur,
        freeformActive: true,
        selected: isMulti ? cur.selected : new Set<string>(),
      };
      return updated;
    });
  };

  const updateFreeformText = (qIdx: number, text: string) => {
    setStates((prev) => {
      const updated = [...prev];
      const cur = updated[qIdx]!;
      updated[qIdx] = { ...cur, freeformText: text, freeformActive: true };
      return updated;
    });
  };

  useKeyboard((key) => {
    // Tab / Shift+Tab — move between questions
    if (key.name === "tab") {
      key.preventDefault?.();
      moveQuestion(key.shift ? -1 : 1);
      return;
    }

    // Esc — skip
    if (key.name === "escape") {
      key.preventDefault?.();
      onSkip();
      return;
    }

    // The freeform <input> handles its own typing/focus — we only need
    // global keys (Tab, Esc) and a way to step out of it via arrow keys.
    if (isOnFreeformRow) {
      if (key.name === "up") {
        key.preventDefault?.();
        focusOption(optionCount - 1);
        return;
      }
      // Enter inside the freeform input is consumed by <input>; nothing to do.
      return;
    }

    // Up / Down — move within the focused question's options
    if (key.name === "up") {
      key.preventDefault?.();
      focusOption(optionFocus - 1);
      return;
    }
    if (key.name === "down") {
      key.preventDefault?.();
      const max = optionCount - 1 + (focusedQuestion.allowFreeform ? 1 : 0);
      focusOption(Math.min(max, optionFocus + 1));
      return;
    }

    // Space — toggle the focused option
    if (key.name === "space") {
      key.preventDefault?.();
      if (optionFocus < optionCount) {
        toggleOption(questionFocus, focusedQuestion.options[optionFocus]!.id);
      } else if (focusedQuestion.allowFreeform && optionFocus === optionCount) {
        enterFreeform(questionFocus);
      }
      return;
    }

    // Enter — submit if all answered, else select / activate
    if (key.name === "return") {
      key.preventDefault?.();
      if (optionFocus < optionCount) {
        toggleOption(questionFocus, focusedQuestion.options[optionFocus]!.id);
        return;
      }
      if (focusedQuestion.allowFreeform && optionFocus === optionCount) {
        enterFreeform(questionFocus);
        return;
      }
      if (allAnswered) {
        onSubmit(buildAnswers(questions, states));
      }
      return;
    }

    // Number keys 1-9 — quick-select option N for the focused question
    if (key.raw && /^[1-9]$/.test(key.raw)) {
      const idx = parseInt(key.raw, 10) - 1;
      if (idx < optionCount) {
        key.preventDefault?.();
        toggleOption(questionFocus, focusedQuestion.options[idx]!.id);
        focusOption(idx);
      }
      return;
    }

    // S — skip
    if (key.raw === "s" || key.raw === "S") {
      key.preventDefault?.();
      onSkip();
      return;
    }

    // Ctrl+Enter — submit unconditionally when answered (escape hatch)
    if (key.ctrl && key.name === "return" && allAnswered) {
      key.preventDefault?.();
      onSubmit(buildAnswers(questions, states));
      return;
    }
  });

  return (
    <box
      flexDirection="column"
      marginTop={1}
      marginLeft={1}
      marginRight={1}
      paddingLeft={1}
      paddingRight={1}
      paddingTop={1}
      paddingBottom={1}
      border={true}
      borderColor={colors.warning}
    >
      {/* Header */}
      <box flexDirection="row" gap={1} marginBottom={1}>
        <text fg={colors.warning}>?</text>
        <text fg={colors.text}>
          The agent is asking {questions.length}{" "}
          {questions.length === 1 ? "question" : "questions"} before continuing.
        </text>
      </box>

      {/* Questions */}
      {questions.map((q, qIdx) => {
        const state = states[qIdx]!;
        const isFocusedQuestion = qIdx === questionFocus;
        const answered = isAnswered(state);

        return (
          <box
            key={q.id}
            flexDirection="column"
            marginTop={qIdx > 0 ? 1 : 0}
            paddingLeft={1}
            border={["left"]}
            borderColor={
              isFocusedQuestion ? colors.primary : colors.borderSubtle
            }
          >
            {/* Question header line */}
            <box flexDirection="row" gap={1}>
              <text fg={isFocusedQuestion ? colors.primary : colors.textMuted}>
                {`Q${qIdx + 1}.`}
              </text>
              <text fg={isFocusedQuestion ? colors.text : colors.textMuted}>
                {q.question}
              </text>
              <text fg={colors.textMuted}>
                {q.multiSelect ? "(multi)" : "(single)"}
              </text>
              {answered && <text fg={colors.success}>✓</text>}
            </box>

            {/* Options */}
            <box flexDirection="column" marginTop={1}>
              {q.options.map((opt, oIdx) => {
                const isSelected = state.selected.has(opt.id);
                const isOptFocused = isFocusedQuestion && oIdx === optionFocus;
                const marker = q.multiSelect
                  ? isSelected
                    ? "[x]"
                    : "[ ]"
                  : isSelected
                    ? "(●)"
                    : "( )";
                return (
                  <box key={opt.id} flexDirection="row" gap={1}>
                    <text fg={isOptFocused ? colors.primary : colors.textMuted}>
                      {isOptFocused ? ">" : " "}
                    </text>
                    <text fg={isSelected ? colors.success : colors.textMuted}>
                      {marker}
                    </text>
                    <text fg={colors.textMuted}>{`${oIdx + 1}.`}</text>
                    <text fg={isSelected ? colors.text : colors.textMuted}>
                      {opt.label}
                    </text>
                    {opt.description && (
                      <text
                        fg={colors.textMuted}
                      >{`— ${opt.description}`}</text>
                    )}
                  </box>
                );
              })}

              {/* Freeform "Other" row */}
              {q.allowFreeform && (
                <box flexDirection="column" marginTop={1}>
                  <box flexDirection="row" gap={1}>
                    <text
                      fg={
                        isFocusedQuestion && optionFocus === optionCount
                          ? colors.primary
                          : colors.textMuted
                      }
                    >
                      {isFocusedQuestion && optionFocus === optionCount
                        ? ">"
                        : " "}
                    </text>
                    <text
                      fg={
                        state.freeformActive ? colors.success : colors.textMuted
                      }
                    >
                      {state.freeformActive ? "[x]" : "[ ]"}
                    </text>
                    <text fg={colors.textMuted}>Other:</text>
                    {/* Render the input only when this question's freeform
                        row is the focused option — otherwise show a static
                        preview to avoid mounting many inputs at once. */}
                    {isFocusedQuestion && optionFocus === optionCount ? (
                      <input
                        width="60%"
                        value={state.freeformText}
                        onInput={(v) => updateFreeformText(qIdx, v)}
                        focused={true}
                        placeholder="Type a freeform answer..."
                        textColor={colors.text}
                        backgroundColor="transparent"
                        cursorColor={colors.textMuted}
                      />
                    ) : (
                      <text
                        fg={state.freeformText ? colors.text : colors.textMuted}
                      >
                        {state.freeformText || "(none)"}
                      </text>
                    )}
                  </box>
                </box>
              )}
            </box>
          </box>
        );
      })}

      {/* Submit hint */}
      <box flexDirection="row" gap={1} marginTop={1}>
        {allAnswered ? (
          <text fg={colors.success}>All answered — press Enter to submit.</text>
        ) : (
          <text fg={colors.textMuted}>
            {`Answer all ${questions.length} questions to enable submit.`}
          </text>
        )}
      </box>

      {/* Footer keybindings */}
      <box flexDirection="row" marginTop={1}>
        <DialogControls
          controls={[
            { key: "Enter", label: "Submit", variant: "primary" },
            { key: "Space", label: "Select" },
            { key: "1-9", label: "Quick Pick" },
            { key: "↑/↓", label: "Option" },
            { key: "Tab", label: "Question" },
            { key: "S", label: "Skip" },
          ]}
        />
      </box>
    </box>
  );
}

export default QuestionsForm;
