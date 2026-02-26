import { useState } from "react";
import { useKeyboard } from "@opentui/react";
import { useRoute } from "../../context/route";
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
  HintBar,
  buildSessionConfig,
} from "./sections";

type WizardStep = "target" | "configure" | "creating";

interface WizardState {
  name: string;
  target: string;
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
  };
  headers: {
    mode: "none" | "default" | "custom";
    customHeaders: Record<string, string>;
  };
}

export default function InitWizard() {
  const { colors } = useTheme();
  const route = useRoute();

  const [state, setState] = useState<WizardState>(() => ({
    name: generateRandomName(),
    target: "",
    auth: { loginUrl: "", username: "", password: "", instructions: "" },
    scope: { allowedHosts: [], allowedPorts: [], strictScope: false },
    headers: { mode: "default", customHeaders: {} },
  }));

  const nav = useWizardNavigation<WizardStep>({
    steps: ["target", "configure", "creating"],
    initialStep: "target",
    layouts: {
      target: { fields: ["name", "url"] },
      configure: {
        sections: {
          auth: {
            fields: ["loginUrl", "username", "password", "instructions"],
          },
          scope: { fields: ["host", "port", "strictScope"] },
          headers: {
            fields:
              state.headers.mode === "custom"
                ? ["mode", "name", "value"]
                : ["mode"],
          },
        },
        sectionOrder: ["auth", "scope", "headers"],
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

  async function createSessionAndNavigate() {
    if (!state.target.trim()) return;
    nav.setStep("creating");
    setError(null);

    try {
      const sessionConfig = buildSessionConfig({
        auth: state.auth,
        scope: state.scope,
        headers: state.headers,
      });

      const session = await sessions.create({
        targets: [state.target],
        name: state.name,
        config: sessionConfig,
      });

      route.navigate({ type: "pentest", sessionId: session.id });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create session");
      nav.setStep("target");
    }
  }

  useKeyboard((key) => {
    if (key.name === "escape") {
      if (nav.currentStep === "creating") return;
      if (nav.currentStep === "configure") {
        nav.setStep("target");
        return;
      }
      route.navigate({ type: "base", path: "home" });
      return;
    }

    if (nav.currentStep === "creating") return;

    // --- Target step ---
    if (nav.currentStep === "target") {
      if (key.name === "tab") {
        if (key.shift) {
          nav.prev();
        } else {
          if (nav.focusedField === 1 && state.target.trim()) {
            nav.setStep("configure");
          } else {
            nav.next();
          }
        }
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

      if (key.name === "tab") {
        if (key.shift) {
          nav.prev();
        } else {
          nav.next();
        }
        return;
      }

      if (key.name === "up" || key.name === "down") {
        // Strict scope toggle
        if (nav.currentSectionName === "scope" && nav.focusedField === 2) {
          setState((prev) => ({
            ...prev,
            scope: { ...prev.scope, strictScope: !prev.scope.strictScope },
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
      }
    }
  });

  if (nav.currentStep === "creating") {
    return <CreatingOverlay target={state.target} />;
  }

  if (nav.currentStep === "target") {
    return (
      <TargetStep
        title="Configure Penetration Test"
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
      />
    );
  }

  // Configure step
  return (
    <box width="100%" flexDirection="column" gap={2} paddingLeft={4}>
      <box flexDirection="column">
        <text fg={colors.text}>Optional Configuration</text>
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

      <HintBar
        hints={[
          { key: "Enter", label: "to start pentest" },
          { key: "Tab", label: "to navigate fields" },
          { key: "ESC", label: "to go back" },
        ]}
      />
    </box>
  );
}
