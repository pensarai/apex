import { useState } from "react";
import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import Input from "../input";
import { useRoute } from "../../context/route";
import { Session } from "../../../core/session";
import { SpinnerDots } from "../sprites";
import { generateRandomName } from "../../../util/name";
import type { OperatorMode, PermissionTier } from "../../../core/operator";
import { OPERATOR_MODES, PERMISSION_TIERS } from "../../../core/operator";

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
}

const greenBullet = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);
const yellowText = RGBA.fromInts(255, 235, 59, 255);
const blueText = RGBA.fromInts(100, 181, 246, 255);

export default function HITLWizard({ initialTarget, initialMode }: HITLWizardProps) {
  const route = useRoute();

  const initialStep: WizardStep = initialTarget ? "mode" : "target";

  const [currentStep, setCurrentStep] = useState<WizardStep>(initialStep);
  const [state, setState] = useState<WizardState>(() => ({
    name: generateRandomName(),
    target: initialTarget || "",
    mode: (initialMode as OperatorMode) || "manual",
    autoApproveTier: 2,
    scope: {
      allowedHosts: [],
      strictScope: false,
    },
  }));

  const [targetFocusedField, setTargetFocusedField] = useState(0);
  const [modeFocusedField, setModeFocusedField] = useState(0);
  const [hostInput, setHostInput] = useState("");
  const [error, setError] = useState<string | null>(null);

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
      if (key.name === "tab") {
        if (key.shift) {
          setTargetFocusedField((prev) => Math.max(0, prev - 1));
        } else {
          if (targetFocusedField === 1 && state.target.trim()) {
            setCurrentStep("mode");
          } else {
            setTargetFocusedField((prev) => Math.min(1, prev + 1));
          }
        }
        return;
      }
      if (key.name === "return" && state.target.trim()) {
        setCurrentStep("mode");
        return;
      }
      return;
    }

    if (currentStep === "mode") {
      if (key.name === "return") {
        // Add host if typing
        if (modeFocusedField === 2 && hostInput.trim()) {
          setState((prev) => ({
            ...prev,
            scope: { ...prev.scope, allowedHosts: [...prev.scope.allowedHosts, hostInput.trim()] },
          }));
          setHostInput("");
          return;
        }
        createSessionAndNavigate();
        return;
      }

      if (key.name === "tab") {
        if (key.shift) {
          setModeFocusedField((prev) => Math.max(0, prev - 1));
        } else {
          setModeFocusedField((prev) => Math.min(3, prev + 1));
        }
        return;
      }

      if (key.name === "up" || key.name === "down") {
        if (modeFocusedField === 0) {
          const modes: OperatorMode[] = ["plan", "manual", "auto"];
          const idx = modes.indexOf(state.mode);
          const newIdx = key.name === "up" ? (idx - 1 + modes.length) % modes.length : (idx + 1) % modes.length;
          setState((prev) => ({ ...prev, mode: modes[newIdx] }));
          return;
        }
        if (modeFocusedField === 1) {
          const tiers: PermissionTier[] = [1, 2, 3, 4, 5];
          const idx = tiers.indexOf(state.autoApproveTier);
          const newIdx = key.name === "up" ? Math.max(0, idx - 1) : Math.min(4, idx + 1);
          setState((prev) => ({ ...prev, autoApproveTier: tiers[newIdx] }));
          return;
        }
        if (modeFocusedField === 3) {
          setState((prev) => ({
            ...prev,
            scope: { ...prev.scope, strictScope: !prev.scope.strictScope },
          }));
          return;
        }
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

  // Mode step
  return (
    <box width="100%" flexDirection="column" gap={2} paddingLeft={4}>
      <box flexDirection="column">
        <text fg={creamText}>Configure Operator Mode</text>
        <text fg={dimText}>Target: {state.target}</text>
      </box>

      {/* Mode Selection */}
      <box flexDirection="column" gap={1}>
        <text fg={modeFocusedField === 0 ? creamText : dimText}>Approval Mode</text>
        <box flexDirection="column" paddingLeft={2}>
          {(["plan", "manual", "auto"] as OperatorMode[]).map((m) => {
            const def = OPERATOR_MODES[m];
            const isSelected = state.mode === m;
            const mColor = m === "plan" ? yellowText : m === "auto" ? greenBullet : blueText;
            return (
              <text key={m} fg={isSelected ? mColor : dimText}>
                {isSelected ? "● " : "○ "}
                <span fg={isSelected ? creamText : dimText}>{def.name}</span>
                <span fg={dimText}> - {def.description}</span>
              </text>
            );
          })}
        </box>
        {modeFocusedField === 0 && <text fg={dimText} paddingLeft={2}>Use ↑/↓ to select</text>}
      </box>

      {/* Auto-approve Tier (only relevant for auto/manual mode) */}
      {state.mode !== "plan" && (
        <box flexDirection="column" gap={1}>
          <text fg={modeFocusedField === 1 ? creamText : dimText}>
            Auto-approve Tier {state.mode === "auto" ? "(actions up to this tier auto-approve)" : "(tier 1 always auto-approves)"}
          </text>
          <box flexDirection="column" paddingLeft={2}>
            {([1, 2, 3, 4, 5] as PermissionTier[]).map((t) => {
              const def = PERMISSION_TIERS[t];
              const isSelected = state.autoApproveTier === t;
              const isEffective = state.mode === "auto" ? t <= state.autoApproveTier : t === 1;
              return (
                <text key={t} fg={isSelected ? greenBullet : isEffective ? creamText : dimText}>
                  {isSelected ? "● " : "○ "}
                  T{t} - {def.name}
                  <span fg={dimText}> ({def.examples.slice(0, 2).join(", ")})</span>
                </text>
              );
            })}
          </box>
          {modeFocusedField === 1 && <text fg={dimText} paddingLeft={2}>Use ↑/↓ to adjust</text>}
        </box>
      )}

      {/* Scope Constraints */}
      <box flexDirection="column" gap={1}>
        <text fg={modeFocusedField === 2 || modeFocusedField === 3 ? creamText : dimText}>Scope Constraints (optional)</text>
        <box flexDirection="column" paddingLeft={2} gap={1}>
          <Input
            label="Add Allowed Host"
            description="Press Enter to add"
            placeholder="example.com"
            value={hostInput}
            onInput={setHostInput}
            focused={modeFocusedField === 2}
          />
          {state.scope.allowedHosts.length > 0 && (
            <box flexDirection="column">
              {state.scope.allowedHosts.map((h, i) => (
                <text key={i} fg={dimText}>• {h}</text>
              ))}
            </box>
          )}
          <box flexDirection="row" gap={1}>
            <text fg={modeFocusedField === 3 ? creamText : dimText}>Strict Scope:</text>
            <text fg={state.scope.strictScope ? greenBullet : dimText}>
              {state.scope.strictScope ? "● Enabled" : "○ Disabled"}
            </text>
            {modeFocusedField === 3 && <text fg={dimText}>(↑/↓ to toggle)</text>}
          </box>
        </box>
      </box>

      <box flexDirection="column" gap={0} marginTop={1}>
        <text>
          <span fg={greenBullet}>█ </span>
          <span fg={dimText}>Press </span>
          <span fg={creamText}>[Enter]</span>
          <span fg={dimText}> to start (</span>
          <span fg={modeColor}>{OPERATOR_MODES[state.mode].name}</span>
          <span fg={dimText}> mode)</span>
        </text>
        <text>
          <span fg={greenBullet}>█ </span>
          <span fg={dimText}>Press </span>
          <span fg={creamText}>[Tab]</span>
          <span fg={dimText}> to navigate fields</span>
        </text>
        <text>
          <span fg={greenBullet}>█ </span>
          <span fg={dimText}>Press </span>
          <span fg={creamText}>[ESC]</span>
          <span fg={dimText}> to go back</span>
        </text>
      </box>
    </box>
  );
}
