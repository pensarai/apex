import { useState } from "react";
import { useKeyboard } from "@opentui/react";
import Input from "../input";
import { useRoute } from "../../context/route";
import { useAgent } from "../../context/agent";
import { sessions } from "../../../core/session";
import { generateRandomName } from "../../../util/name";
import { useTheme } from "../../theme";
import { useWizardNavigation } from "../../hooks/use-wizard-navigation";
import {
  CreatingOverlay,
  TargetStep,
  AuthSection,
  ScopeSection,
  HeadersSection,
  ModelPickerSection,
  useModelPicker,
  HintBar,
  buildSessionConfig,
} from "./sections";

type WizardStep = "target" | "configure" | "creating";

interface WizardState {
  name: string;
  target: string;
  sourceCodeAccess: boolean;
  cwd: string;
  auth: {
    loginUrl: string;
    username: string;
    password: string;
    instructions: string;
  };
  scope: {
    allowedHosts: string[];
    allowedPorts: string[];
    strictScope: boolean;
    enumerateSubdomains: boolean;
  };
  headers: {
    mode: "none" | "default" | "custom";
    customHeaders: Record<string, string>;
  };
}

interface WebWizardProps {
  initialTarget?: string;
  autoMode?: boolean;
  initialName?: string;
  initialAuthUrl?: string;
  initialAuthUser?: string;
  initialAuthPass?: string;
  initialAuthInstructions?: string;
  initialHosts?: string[];
  initialPorts?: number[];
  initialStrict?: boolean;
  initialHeadersMode?: "none" | "default" | "custom";
  initialCustomHeaders?: Record<string, string>;
  initialModel?: string;
}

export default function WebWizard({
  initialTarget,
  autoMode = false,
  initialName,
  initialAuthUrl,
  initialAuthUser,
  initialAuthPass,
  initialAuthInstructions,
  initialHosts,
  initialPorts,
  initialStrict,
  initialHeadersMode,
  initialCustomHeaders,
  initialModel,
}: WebWizardProps) {
  const { colors } = useTheme();
  const route = useRoute();
  const { model, isModelUserSelected } = useAgent();
  const modelPicker = useModelPicker(initialModel);

  const [state, setState] = useState<WizardState>(() => ({
    name: initialName || generateRandomName(),
    target: initialTarget || "",
    sourceCodeAccess: false,
    cwd: process.cwd(),
    auth: {
      loginUrl: initialAuthUrl || "",
      username: initialAuthUser || "",
      password: initialAuthPass || "",
      instructions: initialAuthInstructions || "",
    },
    scope: {
      allowedHosts: initialHosts || [],
      allowedPorts: initialPorts?.map(String) || [],
      strictScope: initialStrict || false,
      enumerateSubdomains: false,
    },
    headers: {
      mode: initialHeadersMode || "default",
      customHeaders: initialCustomHeaders || {},
    },
  }));

  const initialStep: WizardStep = initialTarget ? "configure" : "target";

  const nav = useWizardNavigation<WizardStep>({
    steps: ["target", "configure", "creating"],
    initialStep,
    layouts: {
      target: {
        fields: state.sourceCodeAccess
          ? ["name", "url", "sourceCode", "cwd"]
          : ["name", "url", "sourceCode"],
      },
      configure: {
        sections: {
          auth: {
            fields: ["loginUrl", "username", "password", "instructions"],
          },
          scope: {
            fields: ["host", "port", "strictScope", "enumerateSubdomains"],
          },
          headers: {
            fields:
              state.headers.mode === "custom"
                ? ["mode", "name", "value"]
                : ["mode"],
          },
          model: { fields: ["search"] },
        },
        sectionOrder: ["auth", "scope", "headers", "model"],
      },
      creating: { fields: [] },
    },
  });

  // Input state for list-add fields
  const [hostInput, setHostInput] = useState("");
  const [portInput, setPortInput] = useState("");
  const [headerNameInput, setHeaderNameInput] = useState("");
  const [headerValueInput, setHeaderValueInput] = useState("");
  const [error, setError] = useState<string | null>(null);

  const modeLabel = autoMode ? "Auto Mode" : "Driver Mode";
  const modeDescription = autoMode
    ? "Automated pentesting - agents run autonomously"
    : "Manual orchestration - you direct the agents";

  async function createSessionAndNavigate() {
    if (!state.target.trim()) return;
    nav.setStep("creating");
    setError(null);

    try {
      const sessionConfig = buildSessionConfig({
        sessionType: "web-app",
        mode: autoMode ? "auto" : "driver",
        auth: state.auth,
        scope: state.scope,
        headers: state.headers,
        sourceCodeAccess: state.sourceCodeAccess,
        cwd: state.cwd,
      });

      const session = await sessions.create({
        targets: [state.target],
        name: state.name,
        config: sessionConfig,
      });

      route.navigate({ type: "pentest", sessionId: session.id });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create session");
      nav.setStep(initialTarget ? "configure" : "target");
    }
  }

  useKeyboard((key) => {
    if (key.name === "escape") {
      if (nav.currentStep === "creating") return;
      if (nav.currentStep === "configure") {
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
      const maxField = state.sourceCodeAccess ? 3 : 2;
      if (key.name === "tab") {
        if (key.shift) {
          nav.prev();
        } else {
          if (nav.focusedField === maxField && state.target.trim()) {
            nav.setStep("configure");
          } else {
            nav.next();
          }
        }
        return;
      }
      // Toggle source code access
      if (
        nav.focusedField === 2 &&
        (key.name === "up" || key.name === "down")
      ) {
        setState((prev) => ({
          ...prev,
          sourceCodeAccess: !prev.sourceCodeAccess,
        }));
        return;
      }
      if (key.name === "return" && state.target.trim()) {
        createSessionAndNavigate();
        return;
      }
      return;
    }

    // --- Configure step ---
    if (nav.currentStep === "configure") {
      if (key.name === "return") {
        // Add host
        if (
          nav.currentSectionName === "scope" &&
          nav.focusedField === 0 &&
          hostInput.trim()
        ) {
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
        // Add port
        if (
          nav.currentSectionName === "scope" &&
          nav.focusedField === 1 &&
          portInput.trim()
        ) {
          setState((prev) => ({
            ...prev,
            scope: {
              ...prev.scope,
              allowedPorts: [...prev.scope.allowedPorts, portInput.trim()],
            },
          }));
          setPortInput("");
          return;
        }
        // Add custom header
        if (
          nav.currentSectionName === "headers" &&
          state.headers.mode === "custom" &&
          nav.focusedField === 2 &&
          headerNameInput.trim()
        ) {
          setState((prev) => ({
            ...prev,
            headers: {
              ...prev.headers,
              customHeaders: {
                ...prev.headers.customHeaders,
                [headerNameInput.trim()]: headerValueInput,
              },
            },
          }));
          setHeaderNameInput("");
          setHeaderValueInput("");
          return;
        }
        createSessionAndNavigate();
        return;
      }

      // Tab navigation
      if (key.name === "tab") {
        // Special case: Tab in model section cycles providers
        if (nav.currentSectionName === "model" && !key.shift) {
          const expanded = modelPicker.expandNextProvider();
          if (!expanded) {
            // All expanded — wrap to first section
            nav.setFocusedSection(0);
            nav.setFocusedField(0);
          }
          return;
        }
        if (key.shift) {
          nav.prev();
        } else {
          nav.next();
        }
        return;
      }

      // Arrow keys for toggles and selections
      if (key.name === "up" || key.name === "down") {
        // Strict scope toggle
        if (nav.currentSectionName === "scope" && nav.focusedField === 2) {
          setState((prev) => ({
            ...prev,
            scope: { ...prev.scope, strictScope: !prev.scope.strictScope },
          }));
          return;
        }
        // Enumerate subdomains toggle
        if (nav.currentSectionName === "scope" && nav.focusedField === 3) {
          setState((prev) => ({
            ...prev,
            scope: {
              ...prev.scope,
              enumerateSubdomains: !prev.scope.enumerateSubdomains,
            },
          }));
          return;
        }
        // Headers mode
        if (nav.currentSectionName === "headers" && nav.focusedField === 0) {
          const modes: Array<"none" | "default" | "custom"> = [
            "none",
            "default",
            "custom",
          ];
          const currentIndex = modes.indexOf(state.headers.mode);
          const newIndex =
            key.name === "up"
              ? (currentIndex - 1 + modes.length) % modes.length
              : (currentIndex + 1) % modes.length;
          setState((prev) => ({
            ...prev,
            headers: { ...prev.headers, mode: modes[newIndex]! },
          }));
          return;
        }
        // Model navigation
        if (nav.currentSectionName === "model") {
          modelPicker.navigateModel(key.name as "up" | "down");
          return;
        }
      }

      // Model section: typing, backspace, provider toggle
      if (nav.currentSectionName === "model") {
        if (key.name === "backspace") {
          modelPicker.handleSearchBackspace();
          return;
        }
        if (key.name === "escape" && modelPicker.modelSearchQuery) {
          modelPicker.clearSearch();
          return;
        }
        if (key.name === "left" || key.name === "right") {
          modelPicker.toggleProvider(key.name as "left" | "right");
          return;
        }
        if (
          key.sequence &&
          key.sequence.length === 1 &&
          /[a-zA-Z0-9\-_.]/.test(key.sequence)
        ) {
          modelPicker.handleSearchChar(key.sequence);
          return;
        }
      }
    }
  });

  if (nav.currentStep === "creating") {
    return <CreatingOverlay target={state.target} modeLabel={modeLabel} />;
  }

  if (nav.currentStep === "target") {
    return (
      <TargetStep
        title="Configure Web App Pentest"
        subtitle={modeDescription}
        modelInfo={`Model: ${model.name} [${isModelUserSelected ? "user" : "default"}]`}
        name={state.name}
        target={state.target}
        error={error}
        focusedField={nav.focusedField}
        onNameChange={(v) => setState((prev) => ({ ...prev, name: v }))}
        onTargetChange={(v) => setState((prev) => ({ ...prev, target: v }))}
        hints={[
          { key: "Enter", label: "to start immediately" },
          { key: "Tab", label: "to configure options" },
          { key: "ESC", label: "to cancel" },
        ]}
      >
        {/* Source code access toggle — unique to web wizard */}
        <box flexDirection="column" gap={1}>
          <box flexDirection="row" gap={1}>
            <text
              fg={nav.focusedField === 2 ? colors.primary : colors.textMuted}
            >
              Source Code Access:
            </text>
            <text
              fg={state.sourceCodeAccess ? colors.primary : colors.textMuted}
            >
              {state.sourceCodeAccess ? "● Enabled" : "○ Disabled"}
            </text>
            {nav.focusedField === 2 && (
              <text fg={colors.textMuted}>(↑/↓ to toggle)</text>
            )}
          </box>
          {state.sourceCodeAccess && (
            <Input
              label="Codebase Path"
              description="Path to the source code directory"
              placeholder={process.cwd()}
              value={state.cwd}
              onInput={(v) => setState((prev) => ({ ...prev, cwd: v }))}
              focused={nav.focusedField === 3}
            />
          )}
        </box>
      </TargetStep>
    );
  }

  // Configure step
  return (
    <box width="100%" flexDirection="column" gap={2} paddingLeft={4}>
      <box flexDirection="column">
        <text fg={colors.text}>Configure Web App Pentest - {modeLabel}</text>
        <text fg={colors.textMuted}>Target: {state.target}</text>
        <text fg={colors.textMuted}>
          All fields are optional - configure only what you need
        </text>
      </box>

      <AuthSection
        expanded={nav.focusedSection === 0}
        focusedField={nav.focusedField}
        auth={state.auth}
        onUpdate={(auth) => setState((prev) => ({ ...prev, auth }))}
      />

      <ScopeSection
        expanded={nav.focusedSection === 1}
        focusedField={nav.focusedField}
        scope={state.scope}
        onUpdate={(scope) =>
          setState((prev) => ({
            ...prev,
            scope: { ...prev.scope, ...scope },
          }))
        }
        hostInput={hostInput}
        onHostInputChange={setHostInput}
        portInput={portInput}
        onPortInputChange={setPortInput}
        showSubdomainToggle={true}
      />

      <HeadersSection
        expanded={nav.focusedSection === 2}
        focusedField={nav.focusedField}
        headers={state.headers}
        onUpdate={(headers) => setState((prev) => ({ ...prev, headers }))}
        headerNameInput={headerNameInput}
        onHeaderNameInputChange={setHeaderNameInput}
        headerValueInput={headerValueInput}
        onHeaderValueInputChange={setHeaderValueInput}
      />

      <ModelPickerSection
        expanded={nav.focusedSection === 3}
        picker={modelPicker}
      />

      <HintBar
        hints={[
          { key: "Enter", label: `to start pentest (${modeLabel})` },
          { key: "Tab", label: "to navigate fields" },
          { key: "ESC", label: "to go back" },
        ]}
      />
    </box>
  );
}
