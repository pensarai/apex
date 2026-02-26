import { useState, useCallback, useMemo } from "react";

/**
 * Layout declaration for wizard navigation.
 * Each step has either a flat list of fields or grouped sections of fields.
 */
interface StepLayoutFlat {
  fields: string[];
}

interface StepLayoutSectioned {
  sections: Record<string, { fields: string[] }>;
  /** Ordered list of section keys (since object key order isn't guaranteed semantically) */
  sectionOrder: string[];
}

type StepLayout = StepLayoutFlat | StepLayoutSectioned;

function isSectioned(layout: StepLayout): layout is StepLayoutSectioned {
  return "sections" in layout;
}

interface UseWizardNavigationOptions<TStep extends string> {
  /** Ordered list of steps */
  steps: TStep[];
  /** Layout for each step */
  layouts: Record<TStep, StepLayout>;
  /** Initial step */
  initialStep: TStep;
}

interface WizardNavigation<TStep extends string> {
  /** Current wizard step */
  currentStep: TStep;
  /** Set the current step directly */
  setStep: (step: TStep) => void;

  // --- Flat step navigation (for steps with just fields) ---
  /** Currently focused field index (for flat steps) */
  focusedField: number;
  /** Set focused field index */
  setFocusedField: (index: number) => void;

  // --- Sectioned step navigation ---
  /** Currently focused section index */
  focusedSection: number;
  /** Set focused section index */
  setFocusedSection: (index: number) => void;
  /** Get the field name at the current position */
  currentFieldName: string | undefined;
  /** Get the section name at the current position */
  currentSectionName: string | undefined;

  /** Get the number of fields in a given section (by index) */
  getFieldCount: (sectionIndex: number) => number;
  /** Total number of sections in current step */
  sectionCount: number;

  /** Navigate forward (Tab). Returns 'overflow' if at the end of the current step. */
  next: () => "moved" | "overflow";
  /** Navigate backward (Shift+Tab). Returns 'underflow' if at the beginning. */
  prev: () => "moved" | "underflow";

  /** Reset section/field focus to 0/0 */
  resetFocus: () => void;
}

export function useWizardNavigation<TStep extends string>(
  options: UseWizardNavigationOptions<TStep>,
): WizardNavigation<TStep> {
  const { steps: _steps, layouts, initialStep } = options;

  const [currentStep, setCurrentStep] = useState<TStep>(initialStep);
  const [focusedField, setFocusedField] = useState(0);
  const [focusedSection, setFocusedSection] = useState(0);

  const currentLayout = layouts[currentStep];

  const sectionCount = useMemo(() => {
    if (isSectioned(currentLayout)) {
      return currentLayout.sectionOrder.length;
    }
    return 0;
  }, [currentLayout]);

  const getFieldCount = useCallback(
    (sectionIndex: number): number => {
      if (isSectioned(currentLayout)) {
        const sectionKey = currentLayout.sectionOrder[sectionIndex];
        if (!sectionKey) return 0;
        return currentLayout.sections[sectionKey]?.fields.length ?? 0;
      }
      // Flat layout — sectionIndex is ignored
      return (currentLayout as StepLayoutFlat).fields.length;
    },
    [currentLayout],
  );

  const currentSectionName = useMemo(() => {
    if (isSectioned(currentLayout)) {
      return currentLayout.sectionOrder[focusedSection];
    }
    return undefined;
  }, [currentLayout, focusedSection]);

  const currentFieldName = useMemo(() => {
    if (isSectioned(currentLayout)) {
      const sectionKey = currentLayout.sectionOrder[focusedSection];
      if (!sectionKey) return undefined;
      return currentLayout.sections[sectionKey]?.fields[focusedField];
    }
    return (currentLayout as StepLayoutFlat).fields[focusedField];
  }, [currentLayout, focusedSection, focusedField]);

  const next = useCallback((): "moved" | "overflow" => {
    if (isSectioned(currentLayout)) {
      const sectionKey = currentLayout.sectionOrder[focusedSection];
      if (!sectionKey) return "overflow";
      const maxFields = currentLayout.sections[sectionKey]?.fields.length ?? 0;

      if (focusedField < maxFields - 1) {
        setFocusedField(focusedField + 1);
        return "moved";
      }
      if (focusedSection < currentLayout.sectionOrder.length - 1) {
        setFocusedSection(focusedSection + 1);
        setFocusedField(0);
        return "moved";
      }
      return "overflow";
    }

    // Flat layout
    const flat = currentLayout as StepLayoutFlat;
    if (focusedField < flat.fields.length - 1) {
      setFocusedField(focusedField + 1);
      return "moved";
    }
    return "overflow";
  }, [currentLayout, focusedSection, focusedField]);

  const prev = useCallback((): "moved" | "underflow" => {
    if (isSectioned(currentLayout)) {
      if (focusedField > 0) {
        setFocusedField(focusedField - 1);
        return "moved";
      }
      if (focusedSection > 0) {
        const prevSection = focusedSection - 1;
        const prevSectionKey = currentLayout.sectionOrder[prevSection];
        if (!prevSectionKey) return "underflow";
        const prevMaxFields =
          currentLayout.sections[prevSectionKey]?.fields.length ?? 1;
        setFocusedSection(prevSection);
        setFocusedField(prevMaxFields - 1);
        return "moved";
      }
      return "underflow";
    }

    // Flat layout
    if (focusedField > 0) {
      setFocusedField(focusedField - 1);
      return "moved";
    }
    return "underflow";
  }, [currentLayout, focusedSection, focusedField]);

  const resetFocus = useCallback(() => {
    setFocusedSection(0);
    setFocusedField(0);
  }, []);

  const setStep = useCallback((step: TStep) => {
    setCurrentStep(step);
    setFocusedSection(0);
    setFocusedField(0);
  }, []);

  return {
    currentStep,
    setStep,
    focusedField,
    setFocusedField,
    focusedSection,
    setFocusedSection,
    currentFieldName,
    currentSectionName,
    getFieldCount,
    sectionCount,
    next,
    prev,
    resetFocus,
  };
}
