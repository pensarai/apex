/**
 * Question Component
 *
 * Multi-tab input for complex interactions.
 * Supports various question types with tab navigation.
 *
 * Features:
 * - Tab navigation with arrow keys
 * - Input types: text, yes/no, multiple choice, file picker
 * - Review screen before submission
 */

import { useState, useCallback, useMemo } from "react";
import { useKeyboard } from "@opentui/react";
import { colors } from "../../theme";
import {
  type Question,
  type QuestionComponentProps,
  type AnswerMap,
  type AnswerValue,
  getDefaultValue,
  validateAnswers,
  isTextQuestion,
  isPasswordQuestion,
  isYesNoQuestion,
  isChoiceQuestion,
  isMultiChoiceQuestion,
} from "./types";

// ============================================
// Main Component
// ============================================

export function QuestionComponent({
  questions,
  title,
  description,
  submitLabel = "Submit",
  cancelLabel = "Cancel",
  onSubmit,
  onCancel,
  initialAnswers = {},
  showReview = true,
}: QuestionComponentProps) {
  // Initialize answers with defaults
  const initialAnswerMap = useMemo(() => {
    const map: AnswerMap = {};
    for (const q of questions) {
      map[q.id] = initialAnswers[q.id] ?? getDefaultValue(q);
    }
    return map;
  }, [questions, initialAnswers]);

  const [answers, setAnswers] = useState<AnswerMap>(initialAnswerMap);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [isReviewing, setIsReviewing] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const currentQuestion = questions[currentIndex];
  const isLastQuestion = currentIndex === questions.length - 1;
  const isFirstQuestion = currentIndex === 0;

  // Update answer
  const updateAnswer = useCallback((questionId: string, value: AnswerValue) => {
    setAnswers((prev) => ({
      ...prev,
      [questionId]: value,
    }));
    // Clear error for this question
    setErrors((prev) => {
      const newErrors = { ...prev };
      delete newErrors[questionId];
      return newErrors;
    });
  }, []);

  // Navigate to next question
  const goNext = useCallback(() => {
    if (isReviewing) return;

    // Validate current answer if required
    if (currentQuestion?.required) {
      const answer = answers[currentQuestion.id];
      if (answer === null || answer === undefined || answer === "") {
        setErrors((prev) => ({
          ...prev,
          [currentQuestion.id]: `${currentQuestion.label} is required`,
        }));
        return;
      }
    }

    if (isLastQuestion) {
      if (showReview) {
        setIsReviewing(true);
      } else {
        handleSubmit();
      }
    } else {
      setCurrentIndex((prev) => Math.min(prev + 1, questions.length - 1));
    }
  }, [currentQuestion, answers, isLastQuestion, showReview, questions.length]);

  // Navigate to previous question
  const goPrev = useCallback(() => {
    if (isReviewing) {
      setIsReviewing(false);
      return;
    }
    setCurrentIndex((prev) => Math.max(prev - 1, 0));
  }, [isReviewing]);

  // Handle submission
  const handleSubmit = useCallback(() => {
    const validation = validateAnswers(questions, answers);
    if (!validation.valid) {
      const errorMap: Record<string, string> = {};
      for (const error of validation.errors) {
        errorMap[error.questionId] = error.message;
      }
      setErrors(errorMap);

      // Navigate to first question with error
      const firstErrorIndex = questions.findIndex((q) => errorMap[q.id]);
      if (firstErrorIndex >= 0) {
        setCurrentIndex(firstErrorIndex);
        setIsReviewing(false);
      }
      return;
    }

    onSubmit(answers);
  }, [questions, answers, onSubmit]);

  // Keyboard handling
  useKeyboard((key) => {
    // Navigation
    if (key.name === "tab" && !key.shift) {
      goNext();
      return;
    }
    if (key.name === "tab" && key.shift) {
      goPrev();
      return;
    }
    if (key.name === "down" || key.name === "right") {
      goNext();
      return;
    }
    if (key.name === "up" || key.name === "left") {
      goPrev();
      return;
    }

    // Submit
    if (key.name === "return" && (key.ctrl || isReviewing)) {
      handleSubmit();
      return;
    }

    // Cancel
    if (key.name === "escape" && onCancel) {
      onCancel();
      return;
    }
  });

  // Render review screen
  if (isReviewing) {
    return (
      <ReviewScreen
        questions={questions}
        answers={answers}
        title={title}
        submitLabel={submitLabel}
        cancelLabel={cancelLabel}
        onSubmit={handleSubmit}
        onBack={() => setIsReviewing(false)}
        errors={errors}
      />
    );
  }

  // Render question
  return (
    <box flexDirection="column" width="100%" padding={2}>
      {/* Header */}
      {title && <text fg={colors.creamText}>{title}</text>}
      {description && <text fg={colors.dimText}>{description}</text>}

      {/* Progress indicator */}
      <box flexDirection="row" gap={1} marginTop={1} marginBottom={2}>
        {questions.map((_, idx) => (
          <text
            key={idx}
            fg={idx === currentIndex ? colors.greenAccent : colors.dimText}
          >
            {idx === currentIndex ? "●" : "○"}
          </text>
        ))}
        <text fg={colors.dimText}>
          ({currentIndex + 1}/{questions.length})
        </text>
      </box>

      {/* Current question */}
      {currentQuestion && (
        <QuestionInput
          question={currentQuestion}
          value={answers[currentQuestion.id]}
          onChange={(value) => updateAnswer(currentQuestion.id, value)}
          error={errors[currentQuestion.id]}
          focused={true}
        />
      )}

      {/* Navigation hints */}
      <box flexDirection="row" gap={2} marginTop={2}>
        {!isFirstQuestion && <text fg={colors.dimText}>← Back</text>}
        <text fg={colors.dimText}>
          {isLastQuestion ? (showReview ? "Tab → Review" : "Tab → Submit") : "Tab → Next"}
        </text>
        {onCancel && <text fg={colors.dimText}>ESC Cancel</text>}
      </box>
    </box>
  );
}

// ============================================
// Question Input Component
// ============================================

interface QuestionInputProps {
  question: Question;
  value: AnswerValue;
  onChange: (value: AnswerValue) => void;
  error?: string;
  focused?: boolean;
}

function QuestionInput({
  question,
  value,
  onChange,
  error,
  focused = false,
}: QuestionInputProps) {
  return (
    <box flexDirection="column" gap={1}>
      {/* Label */}
      <box flexDirection="row" gap={1}>
        <text fg={colors.creamText}>
          {question.label}
          {question.required && <text fg={colors.redText}>*</text>}
        </text>
      </box>

      {/* Description */}
      {question.description && (
        <text fg={colors.dimText}>{question.description}</text>
      )}

      {/* Input based on type */}
      {isTextQuestion(question) && (
        <TextInput
          value={(value as string) || ""}
          onChange={onChange}
          placeholder={question.placeholder}
          focused={focused}
        />
      )}

      {isPasswordQuestion(question) && (
        <PasswordInput
          value={(value as string) || ""}
          onChange={onChange}
          placeholder={question.placeholder}
          focused={focused}
        />
      )}

      {isYesNoQuestion(question) && (
        <YesNoInput value={(value as boolean) || false} onChange={onChange} />
      )}

      {isChoiceQuestion(question) && (
        <ChoiceInput
          options={question.options}
          value={(value as string) || ""}
          onChange={onChange}
        />
      )}

      {isMultiChoiceQuestion(question) && (
        <MultiChoiceInput
          options={question.options}
          value={(value as string[]) || []}
          onChange={onChange}
        />
      )}

      {/* Error */}
      {error && <text fg={colors.errorColor}>⚠ {error}</text>}
    </box>
  );
}

// ============================================
// Input Type Components
// ============================================

function TextInput({
  value,
  onChange,
  placeholder,
  focused,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  focused?: boolean;
}) {
  return (
    <box flexDirection="row" gap={1}>
      <text fg={colors.greenAccent}>{">"}</text>
      <input
        width="100%"
        value={value}
        onInput={(v) => onChange(v)}
        placeholder={placeholder || "Enter text..."}
        focused={focused}
        textColor="white"
        backgroundColor="transparent"
      />
    </box>
  );
}

function PasswordInput({
  value,
  onChange,
  placeholder,
  focused,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  focused?: boolean;
}) {
  return (
    <box flexDirection="row" gap={1}>
      <text fg={colors.greenAccent}>{">"}</text>
      <input
        width="100%"
        value={"*".repeat(value.length)}
        onInput={(v) => onChange(v)}
        placeholder={placeholder || "Enter password..."}
        focused={focused}
        textColor="white"
        backgroundColor="transparent"
      />
    </box>
  );
}

function YesNoInput({
  value,
  onChange,
}: {
  value: boolean;
  onChange: (value: boolean) => void;
}) {
  useKeyboard((key) => {
    if (key.name === "y" || key.name === "Y") {
      onChange(true);
    }
    if (key.name === "n" || key.name === "N") {
      onChange(false);
    }
  });

  return (
    <box flexDirection="row" gap={2}>
      <box
        flexDirection="row"
        gap={1}
        onMouseDown={() => onChange(true)}
      >
        <text fg={value ? colors.greenAccent : colors.dimText}>
          {value ? "●" : "○"}
        </text>
        <text fg={value ? colors.creamText : colors.dimText}>Yes</text>
      </box>
      <box
        flexDirection="row"
        gap={1}
        onMouseDown={() => onChange(false)}
      >
        <text fg={!value ? colors.greenAccent : colors.dimText}>
          {!value ? "●" : "○"}
        </text>
        <text fg={!value ? colors.creamText : colors.dimText}>No</text>
      </box>
    </box>
  );
}

function ChoiceInput({
  options,
  value,
  onChange,
}: {
  options: { value: string; label: string; description?: string; disabled?: boolean }[];
  value: string;
  onChange: (value: string) => void;
}) {
  const [focusIndex, setFocusIndex] = useState(
    Math.max(0, options.findIndex((o) => o.value === value))
  );

  useKeyboard((key) => {
    if (key.name === "j" || key.name === "down") {
      setFocusIndex((prev) => Math.min(prev + 1, options.length - 1));
    }
    if (key.name === "k" || key.name === "up") {
      setFocusIndex((prev) => Math.max(prev - 1, 0));
    }
    if (key.name === "return" || key.name === "space") {
      const option = options[focusIndex];
      if (option && !option.disabled) {
        onChange(option.value);
      }
    }
  });

  return (
    <box flexDirection="column" gap={0}>
      {options.map((option, idx) => {
        const isSelected = option.value === value;
        const isFocused = idx === focusIndex;
        const isDisabled = option.disabled;

        return (
          <box
            key={option.value}
            flexDirection="row"
            gap={1}
            onMouseDown={() => !isDisabled && onChange(option.value)}
          >
            <text fg={isFocused ? colors.greenAccent : colors.dimText}>
              {isFocused ? ">" : " "}
            </text>
            <text fg={isSelected ? colors.greenAccent : colors.dimText}>
              {isSelected ? "●" : "○"}
            </text>
            <text
              fg={
                isDisabled
                  ? colors.dimText
                  : isSelected
                  ? colors.creamText
                  : colors.dimText
              }
            >
              {option.label}
            </text>
            {option.description && (
              <text fg={colors.dimText}>- {option.description}</text>
            )}
          </box>
        );
      })}
    </box>
  );
}

function MultiChoiceInput({
  options,
  value,
  onChange,
}: {
  options: { value: string; label: string; description?: string; disabled?: boolean }[];
  value: string[];
  onChange: (value: string[]) => void;
}) {
  const [focusIndex, setFocusIndex] = useState(0);

  const toggleOption = (optionValue: string) => {
    if (value.includes(optionValue)) {
      onChange(value.filter((v) => v !== optionValue));
    } else {
      onChange([...value, optionValue]);
    }
  };

  useKeyboard((key) => {
    if (key.name === "j" || key.name === "down") {
      setFocusIndex((prev) => Math.min(prev + 1, options.length - 1));
    }
    if (key.name === "k" || key.name === "up") {
      setFocusIndex((prev) => Math.max(prev - 1, 0));
    }
    if (key.name === "space") {
      const option = options[focusIndex];
      if (option && !option.disabled) {
        toggleOption(option.value);
      }
    }
  });

  return (
    <box flexDirection="column" gap={0}>
      {options.map((option, idx) => {
        const isSelected = value.includes(option.value);
        const isFocused = idx === focusIndex;
        const isDisabled = option.disabled;

        return (
          <box
            key={option.value}
            flexDirection="row"
            gap={1}
            onMouseDown={() => !isDisabled && toggleOption(option.value)}
          >
            <text fg={isFocused ? colors.greenAccent : colors.dimText}>
              {isFocused ? ">" : " "}
            </text>
            <text fg={isSelected ? colors.greenAccent : colors.dimText}>
              {isSelected ? "☑" : "☐"}
            </text>
            <text
              fg={
                isDisabled
                  ? colors.dimText
                  : isSelected
                  ? colors.creamText
                  : colors.dimText
              }
            >
              {option.label}
            </text>
            {option.description && (
              <text fg={colors.dimText}>- {option.description}</text>
            )}
          </box>
        );
      })}
    </box>
  );
}

// ============================================
// Review Screen
// ============================================

interface ReviewScreenProps {
  questions: Question[];
  answers: AnswerMap;
  title?: string;
  submitLabel: string;
  cancelLabel: string;
  onSubmit: () => void;
  onBack: () => void;
  errors: Record<string, string>;
}

function ReviewScreen({
  questions,
  answers,
  title,
  submitLabel,
  cancelLabel,
  onSubmit,
  onBack,
  errors,
}: ReviewScreenProps) {
  const hasErrors = Object.keys(errors).length > 0;

  return (
    <box flexDirection="column" width="100%" padding={2}>
      {/* Header */}
      <text fg={colors.creamText}>{title || "Review Your Answers"}</text>
      <text fg={colors.dimText}>
        Review your answers before submitting.
      </text>

      {/* Answers */}
      <box flexDirection="column" gap={1} marginTop={2}>
        {questions.map((question) => {
          const answer = answers[question.id];
          const error = errors[question.id];
          const displayValue = formatAnswerForDisplay(question, answer);

          return (
            <box key={question.id} flexDirection="column">
              <box flexDirection="row" gap={2}>
                <text fg={colors.dimText}>{question.label}:</text>
                <text fg={error ? colors.errorColor : colors.creamText}>
                  {displayValue}
                </text>
              </box>
              {error && (
                <text fg={colors.errorColor}>⚠ {error}</text>
              )}
            </box>
          );
        })}
      </box>

      {/* Actions */}
      <box flexDirection="row" gap={4} marginTop={2}>
        <box
          onMouseDown={onBack}
          flexDirection="row"
          gap={1}
        >
          <text fg={colors.dimText}>←</text>
          <text fg={colors.dimText}>Back</text>
        </box>
        <box
          onMouseDown={hasErrors ? undefined : onSubmit}
          flexDirection="row"
          gap={1}
        >
          <text fg={hasErrors ? colors.dimText : colors.greenAccent}>
            {submitLabel}
          </text>
          <text fg={colors.dimText}>(Enter)</text>
        </box>
      </box>
    </box>
  );
}

// ============================================
// Helpers
// ============================================

function formatAnswerForDisplay(question: Question, answer: AnswerValue): string {
  if (answer === null || answer === undefined || answer === "") {
    return "(not answered)";
  }

  switch (question.type) {
    case "yesno":
      return answer ? "Yes" : "No";
    case "password":
      return "********";
    case "choice": {
      const opt = question.options.find((o) => o.value === answer);
      return opt?.label || String(answer);
    }
    case "multichoice": {
      if (!Array.isArray(answer)) return String(answer);
      return answer
        .map((v) => question.options.find((o) => o.value === v)?.label || v)
        .join(", ");
    }
    default:
      return String(answer);
  }
}

// ============================================
// Exports
// ============================================

export * from "./types";
export default QuestionComponent;
