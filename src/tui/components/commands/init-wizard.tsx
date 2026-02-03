import { useState } from "react";
import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import Input from "../input";
import { useRoute } from "../../context/route";
import { Session } from "../../../core/session";
import { SpinnerDots } from "../sprites";
import { generateRandomName } from "../../../util/name";

// Simplified wizard step types
type WizardStep = "target" | "configure" | "creating";

// Simplified wizard state interface
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

// Home view color palette
const greenBullet = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);

export default function InitWizard() {
  const route = useRoute();

  // Wizard state
  const [currentStep, setCurrentStep] = useState<WizardStep>("target");
  const [state, setState] = useState<WizardState>(() => ({
    name: generateRandomName(),
    target: "",
    auth: {
      loginUrl: "",
      username: "",
      password: "",
      instructions: "",
    },
    scope: {
      allowedHosts: [],
      allowedPorts: [],
      strictScope: false,
    },
    headers: {
      mode: "default",
      customHeaders: {},
    },
  }));

  // UI state for target step
  const [targetFocusedField, setTargetFocusedField] = useState(0); // 0=name, 1=target

  // UI state for configure step
  const [focusedSection, setFocusedSection] = useState(0); // 0=auth, 1=scope, 2=headers
  const [focusedField, setFocusedField] = useState(0);
  const [hostInput, setHostInput] = useState("");
  const [portInput, setPortInput] = useState("");
  const [headerNameInput, setHeaderNameInput] = useState("");
  const [headerValueInput, setHeaderValueInput] = useState("");

  // Error state
  const [error, setError] = useState<string | null>(null);

  // Create session and navigate to session route
  async function createSessionAndNavigate() {
    if (!state.target.trim()) return;

    setCurrentStep("creating");
    setError(null);

    try {
      // Build session config
      const sessionConfig: Session.SessionConfig = {};

      // Auth config
      if (state.auth.instructions || state.auth.username) {
        sessionConfig.authenticationInstructions = state.auth.instructions;
        if (state.auth.username) {
          sessionConfig.authCredentials = {
            username: state.auth.username,
            password: state.auth.password,
            loginUrl: state.auth.loginUrl || undefined,
          };
        }
      }

      // Scope constraints
      if (state.scope.allowedHosts.length > 0 || state.scope.allowedPorts.length > 0) {
        sessionConfig.scopeConstraints = {
          allowedHosts: state.scope.allowedHosts,
          allowedPorts: state.scope.allowedPorts.map(p => parseInt(p, 10)).filter(p => !isNaN(p)),
          strictScope: state.scope.strictScope,
        };
      }

      // Headers config
      if (state.headers.mode !== "default") {
        sessionConfig.offensiveHeaders = {
          mode: state.headers.mode,
          headers: state.headers.mode === "custom" ? state.headers.customHeaders : undefined,
        };
      }

      // Create execution session
      // const session = await Session.createExecution({
      //   target: state.target,
      //   objective: `Pentest: ${state.target}`,
      //   prefix: state.name || undefined,
      //   config: sessionConfig,
      // });

      const session = await Session.create({
        targets: [state.target],
        name: state.name,
        config: sessionConfig,
      })

      // Navigate to session route - SessionView will handle execution
      route.navigate({
        type: "session",
        sessionId: session.id,
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create session");
      setCurrentStep("target");
    }
  }

  // Keyboard handling
  useKeyboard((key) => {
    // ESC - Go back or close
    if (key.name === "escape") {
      if (currentStep === "creating") {
        // Can't cancel while creating
        return;
      }
      if (currentStep === "configure") {
        setCurrentStep("target");
        setFocusedSection(0);
        setFocusedField(0);
        return;
      }
      route.navigate({ type: "base", path: "home" });
      return;
    }

    // Don't allow navigation while creating
    if (currentStep === "creating") return;

    // Target step: Enter to start, Tab to navigate/configure
    if (currentStep === "target") {
      // Tab navigation between name and target fields
      if (key.name === "tab") {
        if (key.shift) {
          setTargetFocusedField((prev) => Math.max(0, prev - 1));
        } else {
          if (targetFocusedField === 1 && state.target.trim()) {
            setCurrentStep("configure");
          } else {
            setTargetFocusedField((prev) => Math.min(1, prev + 1));
          }
        }
        return;
      }
      // Enter to start if target is filled
      if (key.name === "return" && state.target.trim()) {
        createSessionAndNavigate();
        return;
      }
      return;
    }

    // Configure step keyboard handling
    if (currentStep === "configure") {
      // Enter to create session
      if (key.name === "return") {
        // Check if we should add an item instead of starting
        if (focusedSection === 1 && focusedField === 0 && hostInput.trim()) {
          setState((prev) => ({
            ...prev,
            scope: { ...prev.scope, allowedHosts: [...prev.scope.allowedHosts, hostInput.trim()] },
          }));
          setHostInput("");
          return;
        }
        if (focusedSection === 1 && focusedField === 1 && portInput.trim()) {
          setState((prev) => ({
            ...prev,
            scope: { ...prev.scope, allowedPorts: [...prev.scope.allowedPorts, portInput.trim()] },
          }));
          setPortInput("");
          return;
        }
        if (focusedSection === 2 && state.headers.mode === "custom" && focusedField === 2 && headerNameInput.trim()) {
          setState((prev) => ({
            ...prev,
            headers: {
              ...prev.headers,
              customHeaders: { ...prev.headers.customHeaders, [headerNameInput.trim()]: headerValueInput },
            },
          }));
          setHeaderNameInput("");
          setHeaderValueInput("");
          return;
        }
        // Otherwise create session
        createSessionAndNavigate();
        return;
      }

      // Tab navigation between sections and fields
      if (key.name === "tab") {
        if (key.shift) {
          if (focusedField > 0) {
            setFocusedField(focusedField - 1);
          } else if (focusedSection > 0) {
            setFocusedSection(focusedSection - 1);
            setFocusedField(getMaxFieldsForSection(focusedSection - 1) - 1);
          }
        } else {
          const maxFields = getMaxFieldsForSection(focusedSection);
          if (focusedField < maxFields - 1) {
            setFocusedField(focusedField + 1);
          } else if (focusedSection < 2) {
            setFocusedSection(focusedSection + 1);
            setFocusedField(0);
          }
        }
        return;
      }

      // Arrow keys for toggles
      if (key.name === "up" || key.name === "down") {
        if (focusedSection === 1 && focusedField === 2) {
          setState((prev) => ({
            ...prev,
            scope: { ...prev.scope, strictScope: !prev.scope.strictScope },
          }));
          return;
        }
        if (focusedSection === 2 && focusedField === 0) {
          const modes: Array<"none" | "default" | "custom"> = ["none", "default", "custom"];
          const currentIndex = modes.indexOf(state.headers.mode);
          const newIndex = key.name === "up"
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

  function getMaxFieldsForSection(section: number): number {
    switch (section) {
      case 0: return 4;
      case 1: return 3;
      case 2: return state.headers.mode === "custom" ? 3 : 1;
      default: return 1;
    }
  }

  // Render creating state
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
        <SpinnerDots label="Creating session..." fg="green" />
        <text fg={dimText}>Target: {state.target}</text>
      </box>
    );
  }

  // Render target step
  if (currentStep === "target") {
    return (
      <box width="100%" flexDirection="column" gap={2} paddingLeft={4}>
        <text fg={creamText}>Configure Penetration Test</text>

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
            <span fg={dimText}> to start immediately</span>
          </text>
          <text>
            <span fg={greenBullet}>█ </span>
            <span fg={dimText}>Press </span>
            <span fg={creamText}>[Tab]</span>
            <span fg={dimText}> to configure options</span>
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

  // Render configure step
  return (
    <box width="100%" flexDirection="column" gap={2} paddingLeft={4}>
      <box flexDirection="column">
        <text fg={creamText}>Optional Configuration</text>
        <text fg={dimText}>All fields are optional - configure only what you need</text>
      </box>

      {/* Auth Section */}
      <box flexDirection="column" gap={1}>
        <text>
          <span fg={greenBullet}>█ </span>
          <span fg={focusedSection === 0 ? creamText : dimText}>Authentication</span>
        </text>
        {focusedSection === 0 && (
          <box flexDirection="column" gap={1} paddingLeft={2}>
            <Input
              label="Login URL"
              placeholder="https://example.com/login"
              value={state.auth.loginUrl}
              onInput={(v) => setState((prev) => ({ ...prev, auth: { ...prev.auth, loginUrl: v } }))}
              focused={focusedField === 0}
            />
            <Input
              label="Username"
              placeholder="admin"
              value={state.auth.username}
              onInput={(v) => setState((prev) => ({ ...prev, auth: { ...prev.auth, username: v } }))}
              focused={focusedField === 1}
            />
            <Input
              label="Password"
              placeholder="••••••••"
              value={state.auth.password}
              onInput={(v) => setState((prev) => ({ ...prev, auth: { ...prev.auth, password: v } }))}
              focused={focusedField === 2}
            />
            <Input
              label="Auth Instructions"
              placeholder="Use OAuth flow, extract bearer token..."
              value={state.auth.instructions}
              onInput={(v) => setState((prev) => ({ ...prev, auth: { ...prev.auth, instructions: v } }))}
              focused={focusedField === 3}
            />
          </box>
        )}
      </box>

      {/* Scope Section */}
      <box flexDirection="column" gap={1}>
        <text>
          <span fg={greenBullet}>█ </span>
          <span fg={focusedSection === 1 ? creamText : dimText}>Scope Constraints</span>
        </text>
        {focusedSection === 1 && (
          <box flexDirection="column" gap={1} paddingLeft={2}>
            <Input
              label="Add Allowed Host"
              description="Press Enter to add"
              placeholder="example.com"
              value={hostInput}
              onInput={setHostInput}
              focused={focusedField === 0}
            />
            {state.scope.allowedHosts.length > 0 && (
              <box flexDirection="column" paddingLeft={2}>
                {state.scope.allowedHosts.map((h, i) => (
                  <text key={i} fg={dimText}>• {h}</text>
                ))}
              </box>
            )}
            <Input
              label="Add Allowed Port"
              description="Press Enter to add"
              placeholder="443"
              value={portInput}
              onInput={setPortInput}
              focused={focusedField === 1}
            />
            {state.scope.allowedPorts.length > 0 && (
              <box flexDirection="column" paddingLeft={2}>
                {state.scope.allowedPorts.map((p, i) => (
                  <text key={i} fg={dimText}>• {p}</text>
                ))}
              </box>
            )}
            <box flexDirection="row" gap={1}>
              <text fg={focusedField === 2 ? creamText : dimText}>Strict Scope:</text>
              <text fg={state.scope.strictScope ? greenBullet : dimText}>
                {state.scope.strictScope ? "● Enabled" : "○ Disabled"}
              </text>
              {focusedField === 2 && <text fg={dimText}>(↑/↓ to toggle)</text>}
            </box>
          </box>
        )}
      </box>

      {/* Headers Section */}
      <box flexDirection="column" gap={1}>
        <text>
          <span fg={greenBullet}>█ </span>
          <span fg={focusedSection === 2 ? creamText : dimText}>Request Headers</span>
        </text>
        {focusedSection === 2 && (
          <box flexDirection="column" gap={1} paddingLeft={2}>
            <box flexDirection="column">
              <text fg={state.headers.mode === "none" ? greenBullet : dimText}>
                {state.headers.mode === "none" ? "●" : "○"} None
              </text>
              <text fg={state.headers.mode === "default" ? greenBullet : dimText}>
                {state.headers.mode === "default" ? "●" : "○"} Default (User-Agent: pensar-apex)
              </text>
              <text fg={state.headers.mode === "custom" ? greenBullet : dimText}>
                {state.headers.mode === "custom" ? "●" : "○"} Custom
              </text>
            </box>
            {focusedField === 0 && <text fg={dimText}>Use ↑/↓ to select</text>}

            {state.headers.mode === "custom" && (
              <box flexDirection="column" gap={1}>
                <Input
                  label="Header Name"
                  placeholder="X-Custom-Header"
                  value={headerNameInput}
                  onInput={setHeaderNameInput}
                  focused={focusedField === 1}
                />
                <Input
                  label="Header Value"
                  placeholder="value"
                  value={headerValueInput}
                  onInput={setHeaderValueInput}
                  focused={focusedField === 2}
                />
                {Object.keys(state.headers.customHeaders).length > 0 && (
                  <box flexDirection="column">
                    {Object.entries(state.headers.customHeaders).map(([k, v]) => (
                      <text key={k} fg={dimText}>• {k}: {v}</text>
                    ))}
                  </box>
                )}
              </box>
            )}
          </box>
        )}
      </box>

      <box flexDirection="column" gap={0} marginTop={1}>
        <text>
          <span fg={greenBullet}>█ </span>
          <span fg={dimText}>Press </span>
          <span fg={creamText}>[Enter]</span>
          <span fg={dimText}> to start pentest</span>
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
