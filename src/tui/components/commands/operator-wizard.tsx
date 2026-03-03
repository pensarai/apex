import { useState, useEffect, useMemo } from "react";
import { useKeyboard } from "@opentui/react";
import Input from "../input";
import { useRoute } from "../../context/route";
import { useConfig } from "../../context/config";
import { useAgent } from "../../context/agent";
import { sessions, type SessionConfig } from "../../../core/session";
import { SpinnerDots } from "../sprites";
import { generateRandomName } from "../../../util/name";
import type { OperatorMode } from "../../../core/operator";
import { OPERATOR_MODES } from "../../../core/operator";
import type { ModelInfo } from "../../../core/ai";
import { getAvailableModels } from "../../../core/providers/utils";
import { useTheme } from "../../theme";

type WizardStep = "target" | "mode" | "creating";

interface WizardState {
  name: string;
  target: string;
  mode: OperatorMode;
  requireApproval: boolean;
  scope: {
    allowedHosts: string[];
    strictScope: boolean;
  };
}

interface HITLWizardProps {
  initialTarget?: string;
  initialMode?: string;
  initialName?: string;
  initialRequireApproval?: boolean;
  initialAuthUrl?: string;
  initialAuthUser?: string;
  initialAuthPass?: string;
  initialAuthInstructions?: string;
  initialHosts?: string[];
  initialStrict?: boolean;
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

/**
 * Parse host from a URL string (includes port if present)
 * e.g., http://localhost:3001 -> localhost:3001
 */
function parseHostFromUrl(url: string): string | null {
  try {
    const parsed = new URL(url);
    return parsed.host; // host includes port, hostname does not
  } catch {
    // Try adding protocol if missing
    try {
      const parsed = new URL(`https://${url}`);
      return parsed.host;
    } catch {
      return null;
    }
  }
}

export default function HITLWizard(props: HITLWizardProps) {
  const { colors } = useTheme();
  const {
    initialTarget,
    initialMode,
    initialName,
    initialRequireApproval,
    initialHosts,
    initialStrict,
    initialModel,
  } = props;

  const route = useRoute();
  const config = useConfig();
  const { model, setModel, isModelUserSelected } = useAgent();

  const initialStep: WizardStep = initialTarget ? "mode" : "target";

  const [currentStep, setCurrentStep] = useState<WizardStep>(initialStep);
  const [state, setState] = useState<WizardState>(() => {
    const hostsFromTarget: string[] = [];
    if (initialTarget) {
      const parsedHost = parseHostFromUrl(initialTarget);
      if (parsedHost) {
        hostsFromTarget.push(parsedHost);
      }
    }
    const combinedHosts = [
      ...new Set([...hostsFromTarget, ...(initialHosts || [])]),
    ];

    return {
      name: initialName || generateRandomName(),
      target: initialTarget || "",
      mode: (initialMode as OperatorMode) || "manual",
      requireApproval: initialRequireApproval ?? true,
      scope: {
        allowedHosts: combinedHosts,
        strictScope: initialStrict || false,
      },
    };
  });

  const [targetFocusedField, setTargetFocusedField] = useState(0);
  const [modeFocusedField, setModeFocusedField] = useState(0);
  const [hostInput, setHostInput] = useState("");
  const [error, setError] = useState<string | null>(null);

  // Model picker state
  const [availableModels, setAvailableModels] = useState<ModelInfo[]>([]);
  const [modelSearchQuery, setModelSearchQuery] = useState("");
  const [expandedProviders, setExpandedProviders] = useState<Set<string>>(
    new Set(["anthropic"]),
  );

  // Load available models
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

  // Group and filter models
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

  // Visible models for navigation
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
    if (!state.target.trim()) return;

    setCurrentStep("creating");
    setError(null);

    try {
      const sessionConfig: SessionConfig = {
        sessionType: "web-app",
        mode: "operator",
        operatorSettings: {
          initialMode: state.mode,
          requireApproval: state.requireApproval,
          enableSuggestions: true,
        },
      };

      if (state.scope.allowedHosts.length > 0) {
        sessionConfig.scopeConstraints = {
          allowedHosts: state.scope.allowedHosts,
          strictScope: state.scope.strictScope,
        };
      }

      const session = await sessions.create({
        targets: [state.target],
        name: state.name,
        config: sessionConfig,
      });

      route.navigate({
        type: "operator",
        sessionId: session.id,
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create session");
      setCurrentStep(initialTarget ? "mode" : "target");
    }
  }

  const goToModeStep = () => {
    const targetHost = parseHostFromUrl(state.target);
    if (targetHost && !state.scope.allowedHosts.includes(targetHost)) {
      setState((prev) => ({
        ...prev,
        scope: {
          ...prev.scope,
          allowedHosts: [targetHost, ...prev.scope.allowedHosts],
        },
      }));
    }
    setCurrentStep("mode");
  };

  // Mode step fields:
  // 0: Mode selection
  // 1: Require approval toggle
  // 2: Add allowed host input
  // 3: Strict scope toggle
  // 4: Model selection
  // 5: Submit button
  const maxField = 5;

  useKeyboard((key) => {
    if (key.name === "escape") {
      if (currentStep === "creating") return;
      if (currentStep === "mode") {
        if (initialTarget) {
          route.navigate({ type: "base", path: "home" });
        } else {
          setCurrentStep("target");
        }
        return;
      }
      route.navigate({ type: "base", path: "home" });
      return;
    }

    if (currentStep === "creating") return;

    if (currentStep === "target") {
      if (key.name === "tab" || key.name === "down") {
        if (key.shift) {
          setTargetFocusedField((prev) => Math.max(0, prev - 1));
        } else {
          if (targetFocusedField === 1 && state.target.trim()) {
            goToModeStep();
          } else {
            setTargetFocusedField((prev) => Math.min(1, prev + 1));
          }
        }
        return;
      }
      if (key.name === "up") {
        setTargetFocusedField((prev) => Math.max(0, prev - 1));
        return;
      }
      if (key.name === "return" && state.target.trim()) {
        goToModeStep();
        return;
      }
      return;
    }

    if (currentStep === "mode") {
      if (key.name === "up") {
        setModeFocusedField((prev) => Math.max(0, prev - 1));
        return;
      }
      if (key.name === "down") {
        setModeFocusedField((prev) => Math.min(maxField, prev + 1));
        return;
      }
      if (key.name === "tab") {
        if (key.shift) {
          setModeFocusedField((prev) => Math.max(0, prev - 1));
        } else {
          setModeFocusedField((prev) => Math.min(maxField, prev + 1));
        }
        return;
      }

      if (key.name === "left" || key.name === "right") {
        const delta = key.name === "left" ? -1 : 1;

        // Mode selection (field 0)
        if (modeFocusedField === 0) {
          const modes: OperatorMode[] = ["plan", "manual", "auto"];
          const idx = modes.indexOf(state.mode);
          const newIdx = (idx + delta + modes.length) % modes.length;
          setState((prev) => ({ ...prev, mode: modes[newIdx] }));
          return;
        }

        // Require approval toggle (field 1)
        if (modeFocusedField === 1) {
          setState((prev) => ({
            ...prev,
            requireApproval: !prev.requireApproval,
          }));
          return;
        }

        // Strict scope toggle (field 3)
        if (modeFocusedField === 3) {
          setState((prev) => ({
            ...prev,
            scope: { ...prev.scope, strictScope: !prev.scope.strictScope },
          }));
          return;
        }

        // Model selection (field 4)
        if (modeFocusedField === 4 && visibleModels.length > 0) {
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
        // Require approval toggle (field 1)
        if (modeFocusedField === 1) {
          setState((prev) => ({
            ...prev,
            requireApproval: !prev.requireApproval,
          }));
          return;
        }

        // Add host if typing (field 2)
        if (modeFocusedField === 2 && hostInput.trim()) {
          setState((prev) => ({
            ...prev,
            scope: {
              ...prev.scope,
              allowedHosts: [...prev.scope.allowedHosts, hostInput.trim()],
            },
          }));
          setHostInput("");
          return;
        }

        // Toggle strict scope (field 3)
        if (modeFocusedField === 3) {
          setState((prev) => ({
            ...prev,
            scope: { ...prev.scope, strictScope: !prev.scope.strictScope },
          }));
          return;
        }

        // Submit button (field 5)
        if (modeFocusedField === 5) {
          createSessionAndNavigate();
        }
        return;
      }
    }
  });

  const modeColor =
    state.mode === "plan"
      ? colors.warning
      : state.mode === "auto"
        ? colors.primary
        : colors.accent;

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
        <SpinnerDots label="Creating HITL session..." fg={colors.primary} />
        <text fg={colors.textMuted}>Target: {state.target}</text>
        <text fg={modeColor}>Mode: {OPERATOR_MODES[state.mode].name}</text>
      </box>
    );
  }

  if (currentStep === "target") {
    return (
      <box width="100%" flexDirection="column" gap={2} paddingLeft={4}>
        <text fg={colors.text}>Interactive Pentesting (Operator Mode)</text>
        <text fg={colors.textMuted}>
          Human-in-the-Loop - Approval gates for risky actions
        </text>

        {error && <text fg={colors.error}>Error: {error}</text>}

        <Input
          label="Session Name"
          description="Auto-generated, edit if desired"
          placeholder="swift-falcon"
          value={state.name}
          onInput={(v) => setState((prev) => ({ ...prev, name: v }))}
          focused={targetFocusedField === 0}
        />

        <Input
          label="Target URL"
          description="e.g., https://example.com"
          placeholder="https://example.com"
          value={state.target}
          onInput={(v) => setState((prev) => ({ ...prev, target: v }))}
          focused={targetFocusedField === 1}
        />

        <box flexDirection="column" gap={0} marginTop={1}>
          <text>
            <span fg={colors.primary}>█ </span>
            <span fg={colors.textMuted}>Press </span>
            <span fg={colors.text}>[Enter]</span>
            <span fg={colors.textMuted}> or </span>
            <span fg={colors.text}>[Tab]</span>
            <span fg={colors.textMuted}> to configure mode</span>
          </text>
          <text>
            <span fg={colors.primary}>█ </span>
            <span fg={colors.textMuted}>Press </span>
            <span fg={colors.text}>[ESC]</span>
            <span fg={colors.textMuted}> to cancel</span>
          </text>
        </box>
      </box>
    );
  }

  const modeDef = OPERATOR_MODES[state.mode];

  return (
    <box width="100%" flexDirection="column" gap={1} paddingLeft={4}>
      <box flexDirection="column" marginBottom={1}>
        <text fg={colors.text}>Configure Operator Mode</text>
        <text fg={colors.textMuted}>Target: {state.target}</text>
      </box>

      {/* Mode Selection - Field 0 */}
      <box flexDirection="row" gap={1}>
        <text fg={modeFocusedField === 0 ? colors.primary : colors.textMuted}>
          {modeFocusedField === 0 ? "▸" : " "}
        </text>
        <text fg={modeFocusedField === 0 ? colors.text : colors.textMuted}>
          Mode:
        </text>
        <text fg={modeColor}>{modeDef.name}</text>
        <text fg={colors.textMuted}>- {modeDef.description}</text>
        {modeFocusedField === 0 && <text fg={colors.textMuted}>(←/→)</text>}
      </box>

      {/* Require Approval Toggle - Field 1 */}
      <box flexDirection="row" gap={1}>
        <text fg={modeFocusedField === 1 ? colors.primary : colors.textMuted}>
          {modeFocusedField === 1 ? "▸" : " "}
        </text>
        <text fg={modeFocusedField === 1 ? colors.text : colors.textMuted}>
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
        {modeFocusedField === 1 && (
          <text fg={colors.textMuted}>(Enter/←/→)</text>
        )}
      </box>

      {/* Add Allowed Host - Field 2 */}
      <box flexDirection="row" gap={1}>
        <text fg={modeFocusedField === 2 ? colors.primary : colors.textMuted}>
          {modeFocusedField === 2 ? "▸" : " "}
        </text>
        <text fg={modeFocusedField === 2 ? colors.text : colors.textMuted}>
          Add host:
        </text>
        {modeFocusedField === 2 ? (
          <input
            width={30}
            value={hostInput}
            onInput={setHostInput}
            focused={true}
            placeholder="example.com"
            textColor={colors.text}
            backgroundColor="transparent"
            cursorColor={colors.textMuted}
          />
        ) : (
          <text fg={colors.textMuted}>{hostInput || "example.com"}</text>
        )}
        {modeFocusedField === 2 && (
          <text fg={colors.textMuted}>(Enter to add)</text>
        )}
      </box>

      {/* Show added hosts */}
      {state.scope.allowedHosts.length > 0 && (
        <box flexDirection="column" paddingLeft={3}>
          {state.scope.allowedHosts.map((h, i) => (
            <text key={i} fg={colors.textMuted}>
              {" "}
              • {h}
            </text>
          ))}
        </box>
      )}

      {/* Strict Scope - Field 3 */}
      <box flexDirection="row" gap={1}>
        <text fg={modeFocusedField === 3 ? colors.primary : colors.textMuted}>
          {modeFocusedField === 3 ? "▸" : " "}
        </text>
        <text fg={modeFocusedField === 3 ? colors.text : colors.textMuted}>
          Strict scope:
        </text>
        <text fg={state.scope.strictScope ? colors.primary : colors.textMuted}>
          {state.scope.strictScope ? "Enabled" : "Disabled"}
        </text>
        {modeFocusedField === 3 && (
          <text fg={colors.textMuted}>(Enter/←/→)</text>
        )}
      </box>

      {/* Model Selection - Field 4 */}
      <box flexDirection="row" gap={1}>
        <text fg={modeFocusedField === 4 ? colors.primary : colors.textMuted}>
          {modeFocusedField === 4 ? "▸" : " "}
        </text>
        <text fg={modeFocusedField === 4 ? colors.text : colors.textMuted}>
          Model:
        </text>
        <text fg={colors.primary}>{model.name}</text>
        {modeFocusedField === 4 && <text fg={colors.textMuted}>(←/→)</text>}
      </box>

      {/* Submit Button - Field 5 */}
      <box flexDirection="row" gap={1} marginTop={1}>
        <text fg={modeFocusedField === 5 ? colors.primary : colors.textMuted}>
          {modeFocusedField === 5 ? "▸" : " "}
        </text>
        <text fg={modeFocusedField === 5 ? colors.primary : colors.textMuted}>
          {modeFocusedField === 5 ? "[" : " "}
        </text>
        <text fg={modeFocusedField === 5 ? colors.text : colors.textMuted}>
          Start Session
        </text>
        <text fg={modeFocusedField === 5 ? colors.primary : colors.textMuted}>
          {modeFocusedField === 5 ? "]" : " "}
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
