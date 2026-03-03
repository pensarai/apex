import { useState, useEffect, useMemo } from "react";
import { useKeyboard } from "@opentui/react";
import { useRoute } from "../../context/route";
import { useConfig } from "../../context/config";
import { useAgent } from "../../context/agent";
import { sessions, type SessionConfig } from "../../../core/session";
import { SpinnerDots } from "../sprites";
import { generateRandomName } from "../../../util/name";
import type { ModelInfo } from "../../../core/ai";
import { getAvailableModels } from "../../../core/providers/utils";
import { useTheme } from "../../theme";

type WizardStep = "config" | "creating";

interface WizardState {
  name: string;
  target: string;
  requireApproval: boolean;
}

interface HITLWizardProps {
  initialTarget?: string;
  initialName?: string;
  initialRequireApproval?: boolean;
  initialAuthUrl?: string;
  initialAuthUser?: string;
  initialAuthPass?: string;
  initialAuthInstructions?: string;
  initialHeadersMode?: "none" | "default" | "custom";
  initialCustomHeaders?: Record<string, string>;
  initialModel?: string;
}

const providerNames: Record<string, string> = {
  anthropic: "Claude",
  openai: "OpenAI",
  openrouter: "OpenRouter",
  bedrock: "Bedrock",
};
const providerOrder = ["anthropic", "openai", "openrouter", "bedrock"];

export default function HITLWizard(props: HITLWizardProps) {
  const { colors } = useTheme();
  const { initialTarget, initialName, initialRequireApproval, initialModel } =
    props;

  const route = useRoute();
  const config = useConfig();
  const { model, setModel, isModelUserSelected } = useAgent();

  const [currentStep, setCurrentStep] = useState<WizardStep>("config");
  const [state, setState] = useState<WizardState>(() => ({
    name: initialName || generateRandomName(),
    target: initialTarget || "",
    requireApproval: initialRequireApproval ?? true,
  }));

  const [focusedField, setFocusedField] = useState(0);
  const [error, setError] = useState<string | null>(null);

  // Model picker state
  const [availableModels, setAvailableModels] = useState<ModelInfo[]>([]);
  const [modelSearchQuery, setModelSearchQuery] = useState("");
  const [expandedProviders, setExpandedProviders] = useState<Set<string>>(
    new Set(["anthropic"]),
  );

  useEffect(() => {
    if (config.data) {
      const models = getAvailableModels(config.data);
      setAvailableModels(models);
      if (models.length > 0) {
        if (initialModel) {
          const targetModel = models.find((m) => m.id === initialModel);
          if (targetModel) {
            setModel(targetModel);
            setExpandedProviders(new Set([targetModel.provider]));
            return;
          }
        }
        const currentModel = models.find((m) => m.id === model.id) || models[0];
        if (currentModel) {
          setExpandedProviders(new Set([currentModel.provider]));
        }
      }
    }
  }, [config.data, model.id, initialModel]);

  const groupedModels = useMemo(() => {
    const groups: Record<string, ModelInfo[]> = {};
    const query = modelSearchQuery.toLowerCase().trim();
    for (const m of availableModels) {
      if (
        query &&
        !m.name.toLowerCase().includes(query) &&
        !m.id.toLowerCase().includes(query)
      ) {
        continue;
      }
      if (!groups[m.provider]) groups[m.provider] = [];
      groups[m.provider].push(m);
    }
    return groups;
  }, [availableModels, modelSearchQuery]);

  const visibleModels = useMemo(() => {
    const result: ModelInfo[] = [];
    for (const provider of providerOrder) {
      const models = groupedModels[provider];
      if (!models || models.length === 0) continue;
      if (expandedProviders.has(provider)) {
        result.push(...models);
      }
    }
    return result;
  }, [groupedModels, expandedProviders]);

  async function createSessionAndNavigate() {
    setCurrentStep("creating");
    setError(null);

    try {
      const sessionConfig: SessionConfig = {
        sessionType: "web-app",
        mode: "operator",
        operatorSettings: {
          initialMode: "auto",
          requireApproval: state.requireApproval,
          enableSuggestions: true,
        },
      };

      const targets = state.target.trim() ? [state.target] : [];
      const session = await sessions.create({
        targets,
        name: state.name,
        config: sessionConfig,
      });

      route.navigate({
        type: "operator",
        sessionId: session.id,
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create session");
      setCurrentStep("config");
    }
  }

  // Config step fields:
  // 0: Session name
  // 1: Require approval toggle
  // 2: Model selection
  // 3: Submit button
  const maxField = 3;

  useKeyboard((key) => {
    if (key.name === "escape") {
      if (currentStep === "creating") return;
      route.navigate({ type: "base", path: "home" });
      return;
    }

    if (currentStep === "creating") return;

    if (currentStep === "config") {
      const isEditingText = focusedField === 0;

      if (key.name === "up") {
        setFocusedField((prev) => Math.max(0, prev - 1));
        return;
      }
      if (key.name === "down") {
        setFocusedField((prev) => Math.min(maxField, prev + 1));
        return;
      }
      if (key.name === "tab") {
        if (key.shift) {
          setFocusedField((prev) => Math.max(0, prev - 1));
        } else {
          setFocusedField((prev) => Math.min(maxField, prev + 1));
        }
        return;
      }

      if (!isEditingText && (key.name === "left" || key.name === "right")) {
        const delta = key.name === "left" ? -1 : 1;

        // Require approval toggle (field 1)
        if (focusedField === 1) {
          setState((prev) => ({
            ...prev,
            requireApproval: !prev.requireApproval,
          }));
          return;
        }

        // Model selection (field 2)
        if (focusedField === 2 && visibleModels.length > 0) {
          const currentIdx = visibleModels.findIndex((m) => m.id === model.id);
          const newIdx = Math.max(
            0,
            Math.min(visibleModels.length - 1, currentIdx + delta),
          );
          const newModel = visibleModels[newIdx];
          if (newModel) setModel(newModel);
          return;
        }
      }

      if (key.name === "return") {
        // Session name (field 0) — advance to next field
        if (focusedField === 0) {
          setFocusedField(1);
          return;
        }

        // Require approval toggle (field 1)
        if (focusedField === 1) {
          setState((prev) => ({
            ...prev,
            requireApproval: !prev.requireApproval,
          }));
          return;
        }

        // Submit button (field 3)
        if (focusedField === 3) {
          createSessionAndNavigate();
        }
        return;
      }
    }
  });

  if (currentStep === "creating") {
    return (
      <box
        flexDirection="column"
        width="100%"
        height="100%"
        alignItems="center"
        justifyContent="center"
        flexGrow={1}
        gap={2}
      >
        <SpinnerDots label="Creating operator session..." fg={colors.primary} />
        <text fg={colors.textMuted}>Session: {state.name}</text>
      </box>
    );
  }

  return (
    <box width="100%" flexDirection="column" gap={1} paddingLeft={4}>
      <box flexDirection="column" marginBottom={1}>
        <text fg={colors.text}>Interactive Pentesting (Operator Mode)</text>
        <text fg={colors.textMuted}>
          Human-in-the-Loop - Approval gates for risky actions
        </text>
      </box>

      {error && <text fg={colors.error}>Error: {error}</text>}

      {/* Session Name - Field 0 */}
      <box flexDirection="row" gap={1}>
        <text fg={focusedField === 0 ? colors.primary : colors.textMuted}>
          {focusedField === 0 ? "▸" : " "}
        </text>
        <text fg={focusedField === 0 ? colors.text : colors.textMuted}>
          Session:
        </text>
        {focusedField === 0 ? (
          <input
            width={30}
            value={state.name}
            onInput={(v: string) =>
              setState((prev) => ({ ...prev, name: v }))
            }
            focused={true}
            placeholder="swift-falcon"
            textColor={colors.text}
            backgroundColor="transparent"
            cursorColor={colors.textMuted}
          />
        ) : (
          <text fg={colors.text}>{state.name}</text>
        )}
      </box>

      {/* Require Approval Toggle - Field 1 */}
      <box flexDirection="row" gap={1}>
        <text fg={focusedField === 1 ? colors.primary : colors.textMuted}>
          {focusedField === 1 ? "▸" : " "}
        </text>
        <text fg={focusedField === 1 ? colors.text : colors.textMuted}>
          Require command approval:
        </text>
        <text fg={state.requireApproval ? colors.warning : colors.primary}>
          {state.requireApproval ? "Enabled" : "Disabled"}
        </text>
        <text fg={colors.textMuted}>
          {state.requireApproval
            ? "- approve each command before execution"
            : "- commands execute automatically"}
        </text>
        {focusedField === 1 && (
          <text fg={colors.textMuted}>(Enter/←/→)</text>
        )}
      </box>

      {/* Model Selection - Field 2 */}
      <box flexDirection="row" gap={1}>
        <text fg={focusedField === 2 ? colors.primary : colors.textMuted}>
          {focusedField === 2 ? "▸" : " "}
        </text>
        <text fg={focusedField === 2 ? colors.text : colors.textMuted}>
          Model:
        </text>
        <text fg={colors.primary}>{model.name}</text>
        {focusedField === 2 && <text fg={colors.textMuted}>(←/→)</text>}
      </box>

      {/* Submit Button - Field 3 */}
      <box flexDirection="row" gap={1} marginTop={1}>
        <text fg={focusedField === 3 ? colors.primary : colors.textMuted}>
          {focusedField === 3 ? "▸" : " "}
        </text>
        <text fg={focusedField === 3 ? colors.primary : colors.textMuted}>
          {focusedField === 3 ? "[" : " "}
        </text>
        <text fg={focusedField === 3 ? colors.text : colors.textMuted}>
          Start Session
        </text>
        <text fg={focusedField === 3 ? colors.primary : colors.textMuted}>
          {focusedField === 3 ? "]" : " "}
        </text>
      </box>

      {/* Help text */}
      <box flexDirection="column" gap={0} marginTop={2}>
        <text fg={colors.textMuted}>
          ↑/↓ navigate | ←/→ change value | Enter select | ESC back
        </text>
      </box>
    </box>
  );
}
