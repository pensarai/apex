import { useState } from "react";
import { useKeyboard } from "@opentui/react";
import { useRoute } from "../../context/route";
import { useAgent } from "../../context/agent";
import { sessions, type SessionConfig } from "../../../core/session";
import { generateRandomName } from "../../../util/name";
import type { OperatorMode, PermissionTier } from "../../../core/operator";
import { OPERATOR_MODES, PERMISSION_TIERS } from "../../../core/operator";
import { useTheme } from "../../theme";
import { useWizardNavigation } from "../../hooks/use-wizard-navigation";
import {
  CreatingOverlay,
  TargetStep,
  useModelPicker,
  parseHostFromUrl,
} from "./sections";

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
  initialHosts?: string[];
  initialStrict?: boolean;
  initialModel?: string;
}

export default function HITLWizard(props: HITLWizardProps) {
  const { colors } = useTheme();
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
  const { model } = useAgent();
  const modelPicker = useModelPicker(initialModel);

  const initialStep: WizardStep = initialTarget ? "mode" : "target";

  const [state, setState] = useState<WizardState>(() => {
    const hostsFromTarget: string[] = [];
    if (initialTarget) {
      const parsedHost = parseHostFromUrl(initialTarget);
      if (parsedHost) hostsFromTarget.push(parsedHost);
    }
    const combinedHosts = [
      ...new Set([...hostsFromTarget, ...(initialHosts || [])]),
    ];

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

  // Mode step fields depend on whether plan mode hides the tier selector
  // Fields: mode(0), tier(1, hidden in plan), host(2), strictScope(3), model(4), submit(5)
  // In plan mode, visible fields: mode(0), host(1), strictScope(2), model(3), submit(4)
  const modeFields =
    state.mode === "plan"
      ? ["mode", "host", "strictScope", "model", "submit"]
      : ["mode", "tier", "host", "strictScope", "model", "submit"];

  const nav = useWizardNavigation<WizardStep>({
    steps: ["target", "mode", "creating"],
    initialStep,
    layouts: {
      target: { fields: ["name", "url"] },
      mode: { fields: modeFields },
      creating: { fields: [] },
    },
  });

  const [hostInput, setHostInput] = useState("");
  const [error, setError] = useState<string | null>(null);

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
    nav.setStep("mode");
  };

  async function createSessionAndNavigate() {
    if (!state.target.trim()) return;
    nav.setStep("creating");
    setError(null);

    try {
      const sessionConfig: SessionConfig = {
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

      const session = await sessions.create({
        targets: [state.target],
        name: state.name,
        config: sessionConfig,
      });

      route.navigate({ type: "operator", sessionId: session.id });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create session");
      nav.setStep(initialTarget ? "mode" : "target");
    }
  }

  useKeyboard((key) => {
    if (key.name === "escape") {
      if (nav.currentStep === "creating") return;
      if (nav.currentStep === "mode") {
        if (initialTarget) {
          route.navigate({ type: "base", path: "home" });
        } else {
          nav.setStep("target");
        }
        return;
      }
      route.navigate({ type: "base", path: "home" });
      return;
    }

    if (nav.currentStep === "creating") return;

    // --- Target step ---
    if (nav.currentStep === "target") {
      if (key.name === "tab" || key.name === "down") {
        if (key.shift) {
          nav.prev();
        } else {
          if (nav.focusedField === 1 && state.target.trim()) {
            goToModeStep();
          } else {
            nav.next();
          }
        }
        return;
      }
      if (key.name === "up") {
        nav.prev();
        return;
      }
      if (key.name === "return" && state.target.trim()) {
        goToModeStep();
        return;
      }
      return;
    }

    // --- Mode step ---
    if (nav.currentStep === "mode") {
      const fieldName = nav.currentFieldName;

      if (key.name === "up") {
        nav.prev();
        return;
      }
      if (key.name === "down") {
        nav.next();
        return;
      }
      if (key.name === "tab") {
        if (key.shift) {
          nav.prev();
        } else {
          nav.next();
        }
        return;
      }

      // Left/right to change values
      if (key.name === "left" || key.name === "right") {
        const delta = key.name === "left" ? -1 : 1;

        if (fieldName === "mode") {
          const modes: OperatorMode[] = ["plan", "manual", "auto"];
          const idx = modes.indexOf(state.mode);
          const newIdx = (idx + delta + modes.length) % modes.length;
          setState((prev) => ({ ...prev, mode: modes[newIdx] }));
          return;
        }

        if (fieldName === "tier") {
          const tiers: PermissionTier[] = [1, 2, 3, 4, 5];
          const idx = tiers.indexOf(state.autoApproveTier);
          const newIdx = Math.max(0, Math.min(4, idx + delta));
          setState((prev) => ({ ...prev, autoApproveTier: tiers[newIdx] }));
          return;
        }

        if (fieldName === "strictScope") {
          setState((prev) => ({
            ...prev,
            scope: { ...prev.scope, strictScope: !prev.scope.strictScope },
          }));
          return;
        }

        if (fieldName === "model") {
          modelPicker.cycleModel(delta);
          return;
        }
      }

      // Enter to activate
      if (key.name === "return") {
        if (fieldName === "host" && hostInput.trim()) {
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
        if (fieldName === "strictScope") {
          setState((prev) => ({
            ...prev,
            scope: { ...prev.scope, strictScope: !prev.scope.strictScope },
          }));
          return;
        }
        if (fieldName === "submit") {
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

  if (nav.currentStep === "creating") {
    return (
      <CreatingOverlay
        target={state.target}
        spinnerLabel="Creating HITL session..."
        modeLabel={OPERATOR_MODES[state.mode].name}
        modeLabelColor={modeColor}
      />
    );
  }

  if (nav.currentStep === "target") {
    return (
      <TargetStep
        title="Interactive Pentesting (Operator Mode)"
        subtitle="Human-in-the-Loop - Approval gates for risky actions"
        name={state.name}
        target={state.target}
        error={error}
        focusedField={nav.focusedField}
        onNameChange={(v) => setState((prev) => ({ ...prev, name: v }))}
        onTargetChange={(v) => setState((prev) => ({ ...prev, target: v }))}
        hints={[
          { key: "Enter] or [Tab", label: "to configure mode" },
          { key: "ESC", label: "to cancel" },
        ]}
      />
    );
  }

  // Mode step
  const fieldName = nav.currentFieldName;
  const modeDef = OPERATOR_MODES[state.mode];
  const tierDef = PERMISSION_TIERS[state.autoApproveTier];

  return (
    <box width="100%" flexDirection="column" gap={1} paddingLeft={4}>
      <box flexDirection="column" marginBottom={1}>
        <text fg={colors.text}>Configure Operator Mode</text>
        <text fg={colors.textMuted}>Target: {state.target}</text>
      </box>

      {/* Mode Selection */}
      <box flexDirection="row" gap={1}>
        <text fg={fieldName === "mode" ? colors.primary : colors.textMuted}>
          {fieldName === "mode" ? "▸" : " "}
        </text>
        <text fg={fieldName === "mode" ? colors.text : colors.textMuted}>
          Mode:
        </text>
        <text fg={modeColor}>{modeDef.name}</text>
        <text fg={colors.textMuted}>- {modeDef.description}</text>
        {fieldName === "mode" && <text fg={colors.textMuted}>(←/→)</text>}
      </box>

      {/* Auto-approve Tier (hidden in plan mode) */}
      {state.mode !== "plan" && (
        <box flexDirection="row" gap={1}>
          <text fg={fieldName === "tier" ? colors.primary : colors.textMuted}>
            {fieldName === "tier" ? "▸" : " "}
          </text>
          <text fg={fieldName === "tier" ? colors.text : colors.textMuted}>
            Auto-approve:
          </text>
          <text fg={colors.primary}>
            T{state.autoApproveTier} - {tierDef.name}
          </text>
          <text fg={colors.textMuted}>
            ({tierDef.examples.slice(0, 2).join(", ")})
          </text>
          {fieldName === "tier" && <text fg={colors.textMuted}>(←/→)</text>}
        </box>
      )}

      {/* Add Allowed Host */}
      <box flexDirection="row" gap={1}>
        <text fg={fieldName === "host" ? colors.primary : colors.textMuted}>
          {fieldName === "host" ? "▸" : " "}
        </text>
        <text fg={fieldName === "host" ? colors.text : colors.textMuted}>
          Add host:
        </text>
        {fieldName === "host" ? (
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
        {fieldName === "host" && (
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

      {/* Strict Scope */}
      <box flexDirection="row" gap={1}>
        <text
          fg={fieldName === "strictScope" ? colors.primary : colors.textMuted}
        >
          {fieldName === "strictScope" ? "▸" : " "}
        </text>
        <text fg={fieldName === "strictScope" ? colors.text : colors.textMuted}>
          Strict scope:
        </text>
        <text fg={state.scope.strictScope ? colors.primary : colors.textMuted}>
          {state.scope.strictScope ? "Enabled" : "Disabled"}
        </text>
        {fieldName === "strictScope" && (
          <text fg={colors.textMuted}>(Enter/←/→)</text>
        )}
      </box>

      {/* Model Selection */}
      <box flexDirection="row" gap={1}>
        <text fg={fieldName === "model" ? colors.primary : colors.textMuted}>
          {fieldName === "model" ? "▸" : " "}
        </text>
        <text fg={fieldName === "model" ? colors.text : colors.textMuted}>
          Model:
        </text>
        <text fg={colors.primary}>{model.name}</text>
        {fieldName === "model" && <text fg={colors.textMuted}>(←/→)</text>}
      </box>

      {/* Submit Button */}
      <box flexDirection="row" gap={1} marginTop={1}>
        <text fg={fieldName === "submit" ? colors.primary : colors.textMuted}>
          {fieldName === "submit" ? "▸" : " "}
        </text>
        <text fg={fieldName === "submit" ? colors.primary : colors.textMuted}>
          {fieldName === "submit" ? "[" : " "}
        </text>
        <text fg={fieldName === "submit" ? colors.text : colors.textMuted}>
          Start Session
        </text>
        <text fg={fieldName === "submit" ? colors.primary : colors.textMuted}>
          {fieldName === "submit" ? "]" : " "}
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
