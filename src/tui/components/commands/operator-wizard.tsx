import { useState, useEffect, useMemo } from "react";
import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import Input from "../input";
import { useRoute } from "../../context/route";
import { useConfig } from "../../context/config";
import { useAgent } from "../../context/agent";
import { Session } from "../../../core/session";
import { SpinnerDots } from "../sprites";
import { generateRandomName } from "../../../util/name";
import type { OperatorMode, PermissionTier } from "../../../core/operator";
import { OPERATOR_MODES, PERMISSION_TIERS } from "../../../core/operator";
import type { ModelInfo } from "../../../core/ai";
import { getAvailableModels } from "../../../core/providers/utils";

type WizardStep = "target" | "mode" | "creating";

interface WizardState {
  name: string;
  target: string;
  mode: OperatorMode;
  autoApproveTier: PermissionTier;
  scope: {
    allowedHosts: string[];
    strictScope: boolean;
  };
}

interface HITLWizardProps {
  initialTarget?: string;
  initialMode?: string;
  initialName?: string;
  initialTier?: number;
  initialAuthUrl?: string;
  initialAuthUser?: string;
  initialAuthPass?: string;
  initialAuthInstructions?: string;
  initialHosts?: string[];
  initialStrict?: boolean;
  initialHeadersMode?: 'none' | 'default' | 'custom';
  initialCustomHeaders?: Record<string, string>;
  initialModel?: string;
}

const greenBullet = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);
const yellowText = RGBA.fromInts(255, 235, 59, 255);
const blueText = RGBA.fromInts(100, 181, 246, 255);

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
  const {
    initialTarget,
    initialMode,
    initialName,
    initialTier,
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
    // Auto-parse host from target URL if provided
    const hostsFromTarget: string[] = [];
    if (initialTarget) {
      const parsedHost = parseHostFromUrl(initialTarget);
      if (parsedHost) {
        hostsFromTarget.push(parsedHost);
      }
    }
    // Combine with any explicitly provided hosts (avoiding duplicates)
    const combinedHosts = [...new Set([...hostsFromTarget, ...(initialHosts || [])])];

    return {
      name: initialName || generateRandomName(),
      target: initialTarget || "",
      mode: (initialMode as OperatorMode) || "manual",
      autoApproveTier: (initialTier || 2) as PermissionTier,
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
  const [expandedProviders, setExpandedProviders] = useState<Set<string>>(new Set(["anthropic"]));

  // Load available models
  useEffect(() => {
    if (config.data) {
      const models = getAvailableModels(config.data);
      setAvailableModels(models);
      if (models.length > 0) {
        // If initialModel was provided, try to set it
        if (initialModel) {
          const targetModel = models.find(m => m.id === initialModel);
          if (targetModel) {
            setModel(targetModel);
            setExpandedProviders(new Set([targetModel.provider]));
            return;
          }
        }
        const currentModel = models.find(m => m.id === model.id) || models[0];
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
      if (query && !m.name.toLowerCase().includes(query) && !m.id.toLowerCase().includes(query)) {
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
      const sessionConfig: Session.SessionConfig = {
        sessionType: "web-app",
        mode: "operator",
        operatorSettings: {
          initialMode: state.mode,
          autoApproveTier: state.autoApproveTier,
          enableSuggestions: true,
        },
      };

      if (state.scope.allowedHosts.length > 0) {
        sessionConfig.scopeConstraints = {
          allowedHosts: state.scope.allowedHosts,
          strictScope: state.scope.strictScope,
        };
      }

      const session = await Session.create({
        targets: [state.target],
        name: state.name,
        config: sessionConfig,
      });

      route.navigate({
        type: "session",
        sessionId: session.id,
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create session");
      setCurrentStep(initialTarget ? "mode" : "target");
    }
  }

  // Helper to transition to mode step and auto-parse host from target
  const goToModeStep = () => {
    // Auto-parse host from target URL if not already in scope
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

  // Calculate max field index (5 normally, 4 if plan mode hides tier selector)
  const maxField = state.mode === "plan" ? 4 : 5;

  // Adjust field index mapping when in plan mode (skip tier field)
  const getActualField = (field: number): number => {
    if (state.mode === "plan" && field >= 1) {
      return field + 1; // Skip tier field (1) in plan mode
    }
    return field;
  };

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
      const actualField = getActualField(modeFocusedField);

      // Up/down navigation between fields
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

      // Left/right to change values within a field
      if (key.name === "left" || key.name === "right") {
        const delta = key.name === "left" ? -1 : 1;

        // Mode selection (field 0)
        if (actualField === 0) {
          const modes: OperatorMode[] = ["plan", "manual", "auto"];
          const idx = modes.indexOf(state.mode);
          const newIdx = (idx + delta + modes.length) % modes.length;
          setState((prev) => ({ ...prev, mode: modes[newIdx] }));
          return;
        }

        // Tier selection (field 1, only in non-plan mode)
        if (actualField === 1) {
          const tiers: PermissionTier[] = [1, 2, 3, 4, 5];
          const idx = tiers.indexOf(state.autoApproveTier);
          const newIdx = Math.max(0, Math.min(4, idx + delta));
          setState((prev) => ({ ...prev, autoApproveTier: tiers[newIdx] }));
          return;
        }

        // Strict scope toggle (field 3)
        if (actualField === 3) {
          setState((prev) => ({
            ...prev,
            scope: { ...prev.scope, strictScope: !prev.scope.strictScope },
          }));
          return;
        }

        // Model selection (field 4)
        if (actualField === 4 && visibleModels.length > 0) {
          const currentIdx = visibleModels.findIndex(m => m.id === model.id);
          const newIdx = Math.max(0, Math.min(visibleModels.length - 1, currentIdx + delta));
          const newModel = visibleModels[newIdx];
          if (newModel) setModel(newModel);
          return;
        }
      }

      // Enter to activate/submit
      if (key.name === "return") {
        // Add host if typing (field 2)
        if (actualField === 2 && hostInput.trim()) {
          setState((prev) => ({
            ...prev,
            scope: { ...prev.scope, allowedHosts: [...prev.scope.allowedHosts, hostInput.trim()] },
          }));
          setHostInput("");
          return;
        }

        // Toggle strict scope (field 3)
        if (actualField === 3) {
          setState((prev) => ({
            ...prev,
            scope: { ...prev.scope, strictScope: !prev.scope.strictScope },
          }));
          return;
        }

        // Submit button (field 5)
        if (actualField === 5) {
          createSessionAndNavigate();
        }
        return;
      }
    }
  });

  const modeColor = state.mode === "plan" ? yellowText : state.mode === "auto" ? greenBullet : blueText;

  if (currentStep === "creating") {
    return (
      <box flexDirection="column" width="100%" height="100%" alignItems="center" justifyContent="center" flexGrow={1} gap={2}>
        <SpinnerDots label="Creating HITL session..." fg="green" />
        <text fg={dimText}>Target: {state.target}</text>
        <text fg={modeColor}>Mode: {OPERATOR_MODES[state.mode].name}</text>
      </box>
    );
  }

  if (currentStep === "target") {
    return (
      <box width="100%" flexDirection="column" gap={2} paddingLeft={4}>
        <text fg={creamText}>Interactive Pentesting (Operator Mode)</text>
        <text fg={dimText}>Human-in-the-Loop - Approval gates for risky actions</text>

        {error && <text fg="red">Error: {error}</text>}

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
            <span fg={greenBullet}>█ </span>
            <span fg={dimText}>Press </span>
            <span fg={creamText}>[Enter]</span>
            <span fg={dimText}> or </span>
            <span fg={creamText}>[Tab]</span>
            <span fg={dimText}> to configure mode</span>
          </text>
          <text>
            <span fg={greenBullet}>█ </span>
            <span fg={dimText}>Press </span>
            <span fg={creamText}>[ESC]</span>
            <span fg={dimText}> to cancel</span>
          </text>
        </box>
      </box>
    );
  }

  // Mode step - field indices:
  // 0: Mode selection
  // 1: Auto-approve tier (hidden in plan mode)
  // 2: Add allowed host input
  // 3: Strict scope toggle
  // 4: Model selection
  // 5: Submit button
  // In plan mode, fields shift: 0, 2, 3, 4, 5 become indices 0, 1, 2, 3, 4

  const actualField = getActualField(modeFocusedField);
  const modeDef = OPERATOR_MODES[state.mode];
  const tierDef = PERMISSION_TIERS[state.autoApproveTier];

  return (
    <box width="100%" flexDirection="column" gap={1} paddingLeft={4}>
      <box flexDirection="column" marginBottom={1}>
        <text fg={creamText}>Configure Operator Mode</text>
        <text fg={dimText}>Target: {state.target}</text>
      </box>

      {/* Mode Selection - Field 0 */}
      <box flexDirection="row" gap={1}>
        <text fg={actualField === 0 ? greenBullet : dimText}>{actualField === 0 ? "▸" : " "}</text>
        <text fg={actualField === 0 ? creamText : dimText}>Mode:</text>
        <text fg={modeColor}>{modeDef.name}</text>
        <text fg={dimText}>- {modeDef.description}</text>
        {actualField === 0 && <text fg={dimText}>(←/→)</text>}
      </box>

      {/* Auto-approve Tier - Field 1 (hidden in plan mode) */}
      {state.mode !== "plan" && (
        <box flexDirection="row" gap={1}>
          <text fg={actualField === 1 ? greenBullet : dimText}>{actualField === 1 ? "▸" : " "}</text>
          <text fg={actualField === 1 ? creamText : dimText}>Auto-approve:</text>
          <text fg={greenBullet}>T{state.autoApproveTier} - {tierDef.name}</text>
          <text fg={dimText}>({tierDef.examples.slice(0, 2).join(", ")})</text>
          {actualField === 1 && <text fg={dimText}>(←/→)</text>}
        </box>
      )}

      {/* Add Allowed Host - Field 2 */}
      <box flexDirection="row" gap={1}>
        <text fg={actualField === 2 ? greenBullet : dimText}>{actualField === 2 ? "▸" : " "}</text>
        <text fg={actualField === 2 ? creamText : dimText}>Add host:</text>
        {actualField === 2 ? (
          <input
            width={30}
            value={hostInput}
            onInput={setHostInput}
            focused={true}
            placeholder="example.com"
            textColor="white"
            backgroundColor="transparent"
          />
        ) : (
          <text fg={dimText}>{hostInput || "example.com"}</text>
        )}
        {actualField === 2 && <text fg={dimText}>(Enter to add)</text>}
      </box>

      {/* Show added hosts */}
      {state.scope.allowedHosts.length > 0 && (
        <box flexDirection="column" paddingLeft={3}>
          {state.scope.allowedHosts.map((h, i) => (
            <text key={i} fg={dimText}>  • {h}</text>
          ))}
        </box>
      )}

      {/* Strict Scope - Field 3 */}
      <box flexDirection="row" gap={1}>
        <text fg={actualField === 3 ? greenBullet : dimText}>{actualField === 3 ? "▸" : " "}</text>
        <text fg={actualField === 3 ? creamText : dimText}>Strict scope:</text>
        <text fg={state.scope.strictScope ? greenBullet : dimText}>
          {state.scope.strictScope ? "Enabled" : "Disabled"}
        </text>
        {actualField === 3 && <text fg={dimText}>(Enter/←/→)</text>}
      </box>

      {/* Model Selection - Field 4 */}
      <box flexDirection="row" gap={1}>
        <text fg={actualField === 4 ? greenBullet : dimText}>{actualField === 4 ? "▸" : " "}</text>
        <text fg={actualField === 4 ? creamText : dimText}>Model:</text>
        <text fg={greenBullet}>{model.name}</text>
        {actualField === 4 && <text fg={dimText}>(←/→)</text>}
      </box>

      {/* Submit Button - Field 5 */}
      <box flexDirection="row" gap={1} marginTop={1}>
        <text fg={actualField === 5 ? greenBullet : dimText}>{actualField === 5 ? "▸" : " "}</text>
        <text fg={actualField === 5 ? greenBullet : dimText}>
          {actualField === 5 ? "[" : " "}
        </text>
        <text fg={actualField === 5 ? creamText : dimText}>
          Start Session
        </text>
        <text fg={actualField === 5 ? greenBullet : dimText}>
          {actualField === 5 ? "]" : " "}
        </text>
      </box>

      {/* Help text */}
      <box flexDirection="column" gap={0} marginTop={2}>
        <text fg={dimText}>↑/↓ navigate | ←/→ change value | Enter select | ESC back</text>
      </box>
    </box>
  );
}
