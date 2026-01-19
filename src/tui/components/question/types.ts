/**
 * Question Component Types
 *
 * Defines types for the multi-tab question/survey component.
 * Supports various input types: text, yes/no, multiple choice, file picker.
 */

// ============================================
// Question Types
// ============================================

export type QuestionType = "text" | "yesno" | "choice" | "multichoice" | "file" | "password";

export interface BaseQuestion {
  id: string;
  label: string;
  description?: string;
  required?: boolean;
  defaultValue?: unknown;
}

export interface TextQuestion extends BaseQuestion {
  type: "text";
  placeholder?: string;
  multiline?: boolean;
  maxLength?: number;
  defaultValue?: string;
}

export interface PasswordQuestion extends BaseQuestion {
  type: "password";
  placeholder?: string;
  defaultValue?: string;
}

export interface YesNoQuestion extends BaseQuestion {
  type: "yesno";
  defaultValue?: boolean;
}

export interface ChoiceQuestion extends BaseQuestion {
  type: "choice";
  options: ChoiceOption[];
  defaultValue?: string;
}

export interface MultiChoiceQuestion extends BaseQuestion {
  type: "multichoice";
  options: ChoiceOption[];
  minSelections?: number;
  maxSelections?: number;
  defaultValue?: string[];
}

export interface FileQuestion extends BaseQuestion {
  type: "file";
  extensions?: string[];
  directory?: boolean;
  defaultValue?: string;
}

export interface ChoiceOption {
  value: string;
  label: string;
  description?: string;
  disabled?: boolean;
}

export type Question =
  | TextQuestion
  | PasswordQuestion
  | YesNoQuestion
  | ChoiceQuestion
  | MultiChoiceQuestion
  | FileQuestion;

// ============================================
// Answer Types
// ============================================

export type AnswerValue = string | boolean | string[] | null;

export interface Answer {
  questionId: string;
  value: AnswerValue;
}

export type AnswerMap = Record<string, AnswerValue>;

// ============================================
// Survey Types
// ============================================

export interface SurveySection {
  id: string;
  title: string;
  description?: string;
  questions: Question[];
}

export interface Survey {
  id: string;
  title: string;
  description?: string;
  sections: SurveySection[];
}

// ============================================
// Validation Types
// ============================================

export interface ValidationError {
  questionId: string;
  message: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
}

// ============================================
// Component Props
// ============================================

export interface QuestionComponentProps {
  questions: Question[];
  title?: string;
  description?: string;
  submitLabel?: string;
  cancelLabel?: string;
  onSubmit: (answers: AnswerMap) => void;
  onCancel?: () => void;
  initialAnswers?: AnswerMap;
  showReview?: boolean;
}

// ============================================
// Helpers
// ============================================

export function isTextQuestion(q: Question): q is TextQuestion {
  return q.type === "text";
}

export function isPasswordQuestion(q: Question): q is PasswordQuestion {
  return q.type === "password";
}

export function isYesNoQuestion(q: Question): q is YesNoQuestion {
  return q.type === "yesno";
}

export function isChoiceQuestion(q: Question): q is ChoiceQuestion {
  return q.type === "choice";
}

export function isMultiChoiceQuestion(q: Question): q is MultiChoiceQuestion {
  return q.type === "multichoice";
}

export function isFileQuestion(q: Question): q is FileQuestion {
  return q.type === "file";
}

export function getDefaultValue(question: Question): AnswerValue {
  if (question.defaultValue !== undefined) {
    return question.defaultValue as AnswerValue;
  }

  switch (question.type) {
    case "text":
    case "password":
    case "file":
      return "";
    case "yesno":
      return false;
    case "choice":
      return question.options[0]?.value || "";
    case "multichoice":
      return [];
    default:
      return null;
  }
}

export function validateAnswers(
  questions: Question[],
  answers: AnswerMap
): ValidationResult {
  const errors: ValidationError[] = [];

  for (const question of questions) {
    const answer = answers[question.id];

    // Check required
    if (question.required) {
      if (answer === null || answer === undefined || answer === "") {
        errors.push({
          questionId: question.id,
          message: `${question.label} is required`,
        });
        continue;
      }

      if (Array.isArray(answer) && answer.length === 0) {
        errors.push({
          questionId: question.id,
          message: `${question.label} is required`,
        });
        continue;
      }
    }

    // Type-specific validation
    if (question.type === "multichoice" && Array.isArray(answer)) {
      const mc = question as MultiChoiceQuestion;
      if (mc.minSelections && answer.length < mc.minSelections) {
        errors.push({
          questionId: question.id,
          message: `Select at least ${mc.minSelections} options`,
        });
      }
      if (mc.maxSelections && answer.length > mc.maxSelections) {
        errors.push({
          questionId: question.id,
          message: `Select at most ${mc.maxSelections} options`,
        });
      }
    }

    if (question.type === "text" && typeof answer === "string") {
      const tq = question as TextQuestion;
      if (tq.maxLength && answer.length > tq.maxLength) {
        errors.push({
          questionId: question.id,
          message: `Maximum length is ${tq.maxLength} characters`,
        });
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}
