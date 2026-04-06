import { useState, useEffect, useRef } from "react";
import { useKeyboard } from "@opentui/react";
import { ScrollBoxRenderable } from "@opentui/core";
import Input from "../input";
import { useConfig } from "../../context/config";
import { useAgent } from "../../context/agent";
import type { SessionConfig } from "../../../core/session";
import { SpinnerDots } from "../sprites";
import { useTheme } from "../../theme";
import { Dialog } from "../../context/dialog";
import DialogLayout from "../dialog-layout";
import {
  getAutoPopulatedHosts,
  getAutoPopulatedPorts,
} from "../../../util/url";
import { createThreatModelPrompt } from "../../../core/utils/prompt";
import {
  combinePromptParts,
  resolveFlagValue,
} from "../../utils/command-flags";
import { scrollToChild } from "../../utils/scroll";
import { ModelPickerDialog } from "../model-picker";

// Wizard state interface
interface WizardState {
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
  prompt: string;
  threatModel: string;
}

// Props for the WebWizard
interface WebWizardProps {
  /** Called when the wizard is dismissed (ESC) */
  onClose: () => void;
  /** Called when the wizard completes and a pentest session should start */
  onStartPentest: (targets: string[], sessionConfig: SessionConfig) => void;
  /** Pre-filled target URL from --target flag */
  initialTarget?: string;
  /** Enable auto mode from --auto flag */
  autoMode?: boolean;
  /** Pre-filled session name */
  initialName?: string;
  /** Pre-filled auth URL */
  initialAuthUrl?: string;
  /** Pre-filled auth username */
  initialAuthUser?: string;
  /** Pre-filled auth password */
  initialAuthPass?: string;
  /** Pre-filled auth instructions */
  initialAuthInstructions?: string;
  /** Pre-filled allowed hosts */
  initialHosts?: string[];
  /** Pre-filled allowed ports */
  initialPorts?: number[];
  /** Enable strict scope */
  initialStrict?: boolean;
  /** Pre-filled headers mode */
  initialHeadersMode?: "none" | "default" | "custom";
  /** Pre-filled custom headers */
  initialCustomHeaders?: Record<string, string>;
  /** Pre-filled model ID */
  initialModel?: string;
  /** Operator-provided guidance for the pentest agent */
  initialPrompt?: string;
  /** Pre-resolved threat model content (already wrapped by parseWebFlags) */
  initialThreatModel?: string;
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export default function WebWizard({
  onClose,
  onStartPentest,
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
  initialPrompt,
  initialThreatModel,
}: WebWizardProps) {
  const { colors } = useTheme();
  const config = useConfig();
  const { model, setModel, isModelUserSelected } = useAgent();

  // Set initial model if provided
  useEffect(() => {
    if (config.data && initialModel) {
      const { getAvailableModels } = require("../../../core/providers/utils");
      const models = getAvailableModels(config.data);
      const targetModel = models.find(
        (m: { id: string }) => m.id === initialModel,
      );
      if (targetModel) {
        setModel(targetModel, false);
      }
    }
  }, [config.data, initialModel]);

  // Model picker overlay state
  const [showModelPicker, setShowModelPicker] = useState(false);

  // Wizard state
  const [creating, setCreating] = useState(false);
  const [state, setState] = useState<WizardState>(() => {
    // Auto-populate hosts and ports from target URL
    const autoHosts = initialTarget
      ? getAutoPopulatedHosts(initialTarget, initialHosts || [])
      : initialHosts || [];
    const autoPorts = initialTarget
      ? getAutoPopulatedPorts(initialTarget, initialPorts || [])
      : initialPorts || [];

    return {
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
        allowedHosts: autoHosts,
        allowedPorts: autoPorts.map(String),
        strictScope: initialStrict || false,
        enumerateSubdomains: false,
      },
      headers: {
        mode: initialHeadersMode || "default",
        customHeaders: initialCustomHeaders || {},
      },
      prompt: initialPrompt || "",
      threatModel: initialThreatModel || "",
    };
  });

  // UI state — single flat field index
  const [focusedField, setFocusedField] = useState(0);
  const [advancedExpanded, setAdvancedExpanded] = useState(false);
  // Track whether the threat model value was pre-wrapped by CLI flag parsing
  const [threatModelPreWrapped, setThreatModelPreWrapped] =
    useState(!!initialThreatModel);
  const [hostInput, setHostInput] = useState("");
  const [portInput, setPortInput] = useState("");
  const [headerNameInput, setHeaderNameInput] = useState("");
  const [headerValueInput, setHeaderValueInput] = useState("");

  // Error state
  const [error, setError] = useState<string | null>(null);
  const [targetError, setTargetError] = useState<string | null>(null);

  // Scrollbox ref for scroll-to-focused
  const scrollboxRef = useRef<ScrollBoxRenderable | null>(null);

  // --- Field index computation ---
  // Fields:
  //   0: Target URL
  //   1: Source Code Access toggle
  //   2: Cwd path (only when source code access enabled)
  //   next: Advanced toggle
  //   --- when advanced expanded ---
  //   next: Prompt
  //   next: Threat Model
  //   next: Auth - Login URL
  //   next: Auth - Username
  //   next: Auth - Password
  //   next: Auth - Instructions
  //   next: Scope - Add Host
  //   next: Scope - Add Port
  //   next: Scope - Strict Scope toggle
  //   next: Scope - Enumerate Subdomains toggle
  //   next: Headers Mode (cycle)
  //   next: Header Name (only when custom)
  //   next: Header Value (only when custom)

  const cwdFieldIndex = state.sourceCodeAccess ? 2 : -1;
  const advancedToggleIndex = state.sourceCodeAccess ? 3 : 2;

  // Advanced sub-field indices (only valid when advancedExpanded)
  const promptFieldIndex = advancedToggleIndex + 1;
  const threatModelFieldIndex = promptFieldIndex + 1;
  const authLoginUrlIndex = threatModelFieldIndex + 1;
  const authUsernameIndex = authLoginUrlIndex + 1;
  const authPasswordIndex = authUsernameIndex + 1;
  const authInstructionsIndex = authPasswordIndex + 1;
  const scopeHostIndex = authInstructionsIndex + 1;
  const scopePortIndex = scopeHostIndex + 1;
  const scopeStrictIndex = scopePortIndex + 1;
  const scopeSubdomainIndex = scopeStrictIndex + 1;
  const headersModeIndex = scopeSubdomainIndex + 1;
  const headersNameIndex =
    state.headers.mode === "custom" ? headersModeIndex + 1 : -1;
  const headersValueIndex =
    state.headers.mode === "custom" ? headersModeIndex + 2 : -1;

  const lastFieldIndex =
    state.headers.mode === "custom" ? headersValueIndex : headersModeIndex;
  const totalFields = advancedExpanded
    ? lastFieldIndex + 1
    : advancedToggleIndex + 1;

  // Scroll to the focused field when it changes
  useEffect(() => {
    scrollToChild(scrollboxRef.current, `field-${focusedField}`);
  }, [focusedField]);

  // Auto-populate scope hosts/ports when the user changes the target URL.
  // Only fires when the user hasn't manually edited the scope fields yet.
  const [scopeManuallyEdited, setScopeManuallyEdited] = useState(false);
  useEffect(() => {
    if (scopeManuallyEdited) return;
    const target = state.target.trim();
    if (!target) return;
    setState((prev) => {
      const autoHosts = getAutoPopulatedHosts(target, prev.scope.allowedHosts);
      const autoPorts = getAutoPopulatedPorts(
        target,
        prev.scope.allowedPorts.map(Number).filter((p) => !isNaN(p)),
      );
      return {
        ...prev,
        scope: {
          ...prev.scope,
          allowedHosts: autoHosts,
          allowedPorts: autoPorts.map(String),
        },
      };
    });
  }, [state.target]);

  // Create session and navigate to session route
  async function createSessionAndNavigate() {
    if (!state.target.trim()) {
      setTargetError("Target URL is required");
      setFocusedField(0);
      return;
    }

    setCreating(true);
    setError(null);

    try {
      // Build session config
      const sessionConfig: SessionConfig = {
        sessionType: "web-app",
        mode: autoMode ? "auto" : "driver",
      };

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
      if (
        state.scope.allowedHosts.length > 0 ||
        state.scope.allowedPorts.length > 0
      ) {
        sessionConfig.scopeConstraints = {
          allowedHosts: state.scope.allowedHosts,
          allowedPorts: state.scope.allowedPorts
            .map((p) => parseInt(p, 10))
            .filter((p) => !isNaN(p)),
          strictScope: state.scope.strictScope,
        };
      }

      // Subdomain enumeration
      if (state.scope.enumerateSubdomains) {
        sessionConfig.enumerateSubdomains = true;
      }

      // Source code access (whitebox mode)
      if (state.sourceCodeAccess && state.cwd.trim()) {
        sessionConfig.codebasePath = state.cwd.trim();
      }

      // Headers config
      if (state.headers.mode !== "default") {
        sessionConfig.offensiveHeaders = {
          mode: state.headers.mode,
          headers:
            state.headers.mode === "custom"
              ? state.headers.customHeaders
              : undefined,
        };
      }

      // Operator guidance — combine threat model and prompt.
      // Resolve @filepath references for values typed in the wizard.
      // Values from CLI flags (threatModelPreWrapped) are already resolved.
      const rawPrompt = state.prompt.trim();
      const resolvedPrompt = rawPrompt
        ? resolveFlagValue(rawPrompt)
        : undefined;
      const rawTm = state.threatModel.trim();
      const resolvedTm = rawTm
        ? threatModelPreWrapped
          ? rawTm
          : createThreatModelPrompt(resolveFlagValue(rawTm))
        : undefined;
      const combinedPrompt = combinePromptParts(resolvedTm, resolvedPrompt);
      if (combinedPrompt) {
        sessionConfig.prompt = combinedPrompt;
      }

      onStartPentest([state.target], sessionConfig);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create session");
      setCreating(false);
    }
  }

  // Keyboard handling
  useKeyboard((key) => {
    // Don't capture keys when model picker is showing
    if (showModelPicker) return;

    // ESC - close
    if (key.name === "escape") {
      key.preventDefault();
      if (creating) return;
      onClose();
      return;
    }

    // Don't allow navigation while creating
    if (creating) return;

    // Ctrl+O — open model picker overlay
    if (key.ctrl && key.name === "o") {
      key.preventDefault();
      setShowModelPicker(true);
      return;
    }

    // Enter — start pentest or add item
    if (key.name === "return") {
      key.preventDefault();

      // Add host
      if (
        focusedField === scopeHostIndex &&
        hostInput.trim() &&
        advancedExpanded
      ) {
        setScopeManuallyEdited(true);
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
        focusedField === scopePortIndex &&
        portInput.trim() &&
        advancedExpanded
      ) {
        setScopeManuallyEdited(true);
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
        focusedField === headersValueIndex &&
        headerNameInput.trim() &&
        advancedExpanded
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
        setFocusedField(headersNameIndex);
        return;
      }

      // Otherwise start pentest
      createSessionAndNavigate();
      return;
    }

    // Shift+Tab — toggle/cycle values
    if (key.shift && key.name === "tab") {
      key.preventDefault();
      // Source code access toggle
      if (focusedField === 1) {
        setState((prev) => ({
          ...prev,
          sourceCodeAccess: !prev.sourceCodeAccess,
        }));
        return;
      }
      // Advanced toggle
      if (focusedField === advancedToggleIndex) {
        setAdvancedExpanded((prev) => !prev);
        return;
      }
      // Strict scope toggle
      if (focusedField === scopeStrictIndex && advancedExpanded) {
        setState((prev) => ({
          ...prev,
          scope: { ...prev.scope, strictScope: !prev.scope.strictScope },
        }));
        return;
      }
      // Enumerate subdomains toggle
      if (focusedField === scopeSubdomainIndex && advancedExpanded) {
        setState((prev) => ({
          ...prev,
          scope: {
            ...prev.scope,
            enumerateSubdomains: !prev.scope.enumerateSubdomains,
          },
        }));
        return;
      }
      // Headers mode cycle
      if (focusedField === headersModeIndex && advancedExpanded) {
        const modes = ["none", "default", "custom"] as const;
        const idx = modes.indexOf(state.headers.mode);
        const newIdx = (idx + 1) % modes.length;
        setState((prev) => ({
          ...prev,
          headers: { ...prev.headers, mode: modes[newIdx] },
        }));
        return;
      }
      return;
    }

    // Up/Down — navigate between fields
    if (key.name === "up" || key.name === "down") {
      key.preventDefault();
      const delta = key.name === "down" ? 1 : -1;

      // Auto-expand advanced when pressing down on the toggle
      if (
        focusedField === advancedToggleIndex &&
        delta > 0 &&
        !advancedExpanded
      ) {
        setAdvancedExpanded(true);
        setFocusedField(advancedToggleIndex + 1);
        return;
      }

      // Default: navigate between fields
      const next = focusedField + delta;
      if (next >= 0 && next < totalFields) {
        setFocusedField(next);
      }
      return;
    }
  });

  // Get mode label for display
  const modeLabel = autoMode ? "Auto Mode" : "Driver Mode";
  const modeDescription = autoMode
    ? "Automated pentesting - agents run autonomously"
    : "Manual orchestration - you direct the agents";

  // Render creating state
  if (creating) {
    return (
      <Dialog size="large" onClose={onClose}>
        <DialogLayout title="Creating Session" escLabel={null}>
          <box
            flexDirection="column"
            width="100%"
            height="100%"
            alignItems="center"
            justifyContent="center"
            flexGrow={1}
            gap={2}
          >
            <SpinnerDots label="Creating session..." fg={colors.primary} />
            <text fg={colors.textMuted}>Target: {state.target}</text>
            <text fg={colors.textMuted}>Mode: {modeLabel}</text>
          </box>
        </DialogLayout>
      </Dialog>
    );
  }

  // Section divider helper
  const sectionDivider = (label: string) => (
    <text fg={colors.textMuted}>
      {"── "}
      {label}
      {" ──────────────────────────────"}
    </text>
  );

  // Toggle field helper
  const toggleHint = "(Shift+Tab to toggle)";
  const cycleHint = "(Shift+Tab to cycle)";

  // Model picker — replaces the wizard dialog, Esc returns to wizard
  if (showModelPicker) {
    return <ModelPickerDialog onClose={() => setShowModelPicker(false)} />;
  }

  // Single-page wizard render
  return (
    <Dialog size="large" onClose={onClose}>
      <DialogLayout
        title={`Configure Web App Pentest - ${modeLabel}`}
        footerActions={[
          { key: "Enter", label: "start pentest", variant: "primary" },
          { key: "↑/↓", label: "navigate" },
          { key: "Ctrl+O", label: "select model" },
        ]}
      >
        <scrollbox
          ref={scrollboxRef}
          style={{
            rootOptions: { flexGrow: 1, width: "100%" },
            contentOptions: {
              flexDirection: "column",
              gap: 1,
              paddingBottom: 1,
            },
          }}
          stickyScroll={false}
        >
          <box flexDirection="column">
            <text fg={colors.textMuted}>{modeDescription}</text>
            <text fg={colors.textMuted}>
              Model: {model.name} [{isModelUserSelected ? "user" : "default"}]
            </text>
          </box>

          {error && <text fg={colors.error}>Error: {error}</text>}

          {/* Target URL */}
          <box id={`field-${0}`}>
            <Input
              label="Target URL"
              description="e.g., https://example.com"
              placeholder="https://example.com"
              value={state.target}
              onInput={(v) => {
                setTargetError(null);
                setState((prev) => ({ ...prev, target: v }));
              }}
              onPaste={(event) => {
                const cleaned = String(event.text).replace(/\r?\n/g, " ");
                setTargetError(null);
                setState((prev) => ({
                  ...prev,
                  target: prev.target + cleaned,
                }));
              }}
              focused={focusedField === 0}
            />
          </box>
          {targetError && <text fg={colors.error}>{targetError}</text>}

          {/* Source Code Access */}
          <box id={`field-${1}`} flexDirection="column" gap={1}>
            <box flexDirection="row" gap={1}>
              <text fg={focusedField === 1 ? colors.primary : colors.textMuted}>
                Source Code Access:
              </text>
              <text
                fg={state.sourceCodeAccess ? colors.primary : colors.textMuted}
              >
                {state.sourceCodeAccess ? "● Enabled" : "○ Disabled"}
              </text>
              {focusedField === 1 && (
                <text fg={colors.textMuted}>{toggleHint}</text>
              )}
            </box>
            {state.sourceCodeAccess && (
              <box id={`field-${cwdFieldIndex}`}>
                <Input
                  label="Codebase Path"
                  description="Path to the source code directory"
                  placeholder={process.cwd()}
                  value={state.cwd}
                  onInput={(v) => setState((prev) => ({ ...prev, cwd: v }))}
                  focused={focusedField === cwdFieldIndex}
                />
              </box>
            )}
          </box>

          {/* Advanced toggle */}
          <box id={`field-${advancedToggleIndex}`} flexDirection="row" gap={1}>
            <text
              fg={
                focusedField === advancedToggleIndex
                  ? colors.primary
                  : colors.textMuted
              }
            >
              {advancedExpanded ? "▾" : "▸"} Advanced
            </text>
            {focusedField === advancedToggleIndex && (
              <text fg={colors.textMuted}>{toggleHint}</text>
            )}
          </box>

          {advancedExpanded && (
            <>
              {/* Prompt */}
              <box id={`field-${promptFieldIndex}`}>
                <Input
                  label="Prompt"
                  description="Guidance for the pentest agent (use @filepath to load from file)"
                  placeholder="Focus on authentication bypass..."
                  value={state.prompt}
                  onInput={(v) => setState((prev) => ({ ...prev, prompt: v }))}
                  onPaste={(event) => {
                    const cleaned = String(event.text).replace(/\r?\n/g, " ");
                    setState((prev) => ({
                      ...prev,
                      prompt: prev.prompt + cleaned,
                    }));
                  }}
                  focused={focusedField === promptFieldIndex}
                />
              </box>

              {/* Threat Model */}
              <box id={`field-${threatModelFieldIndex}`}>
                <Input
                  label="Threat Model"
                  description="Threat model content (use @filepath to load from file)"
                  placeholder="@./threat-model.md"
                  value={state.threatModel}
                  onInput={(v) => {
                    setThreatModelPreWrapped(false);
                    setState((prev) => ({ ...prev, threatModel: v }));
                  }}
                  onPaste={(event) => {
                    setThreatModelPreWrapped(false);
                    const cleaned = String(event.text).replace(/\r?\n/g, " ");
                    setState((prev) => ({
                      ...prev,
                      threatModel: prev.threatModel + cleaned,
                    }));
                  }}
                  focused={focusedField === threatModelFieldIndex}
                />
              </box>

              {/* Authentication */}
              {sectionDivider("Authentication")}

              <box id={`field-${authLoginUrlIndex}`}>
                <Input
                  label="Login URL"
                  placeholder="https://example.com/login"
                  value={state.auth.loginUrl}
                  onInput={(v) =>
                    setState((prev) => ({
                      ...prev,
                      auth: { ...prev.auth, loginUrl: v },
                    }))
                  }
                  onPaste={(event) => {
                    const cleaned = String(event.text).replace(/\r?\n/g, " ");
                    setState((prev) => ({
                      ...prev,
                      auth: {
                        ...prev.auth,
                        loginUrl: prev.auth.loginUrl + cleaned,
                      },
                    }));
                  }}
                  focused={focusedField === authLoginUrlIndex}
                />
              </box>
              <box id={`field-${authUsernameIndex}`}>
                <Input
                  label="Username"
                  placeholder="admin"
                  value={state.auth.username}
                  onInput={(v) =>
                    setState((prev) => ({
                      ...prev,
                      auth: { ...prev.auth, username: v },
                    }))
                  }
                  onPaste={(event) => {
                    const cleaned = String(event.text).replace(/\r?\n/g, " ");
                    setState((prev) => ({
                      ...prev,
                      auth: {
                        ...prev.auth,
                        username: prev.auth.username + cleaned,
                      },
                    }));
                  }}
                  focused={focusedField === authUsernameIndex}
                />
              </box>
              <box id={`field-${authPasswordIndex}`}>
                <Input
                  label="Password"
                  placeholder="••••••••"
                  value={state.auth.password}
                  onInput={(v) =>
                    setState((prev) => ({
                      ...prev,
                      auth: { ...prev.auth, password: v },
                    }))
                  }
                  onPaste={(event) => {
                    const cleaned = String(event.text).replace(/\r?\n/g, " ");
                    setState((prev) => ({
                      ...prev,
                      auth: {
                        ...prev.auth,
                        password: prev.auth.password + cleaned,
                      },
                    }));
                  }}
                  focused={focusedField === authPasswordIndex}
                />
              </box>
              <box id={`field-${authInstructionsIndex}`}>
                <Input
                  label="Auth Instructions"
                  placeholder="Use OAuth flow, extract bearer token..."
                  value={state.auth.instructions}
                  onInput={(v) =>
                    setState((prev) => ({
                      ...prev,
                      auth: { ...prev.auth, instructions: v },
                    }))
                  }
                  onPaste={(event) => {
                    const cleaned = String(event.text).replace(/\r?\n/g, " ");
                    setState((prev) => ({
                      ...prev,
                      auth: {
                        ...prev.auth,
                        instructions: prev.auth.instructions + cleaned,
                      },
                    }));
                  }}
                  focused={focusedField === authInstructionsIndex}
                />
              </box>

              {/* Scope */}
              {sectionDivider("Scope")}

              <box id={`field-${scopeHostIndex}`}>
                <Input
                  label="Add Allowed Host"
                  description="Press Enter to add"
                  placeholder="example.com"
                  value={hostInput}
                  onInput={setHostInput}
                  focused={focusedField === scopeHostIndex}
                />
              </box>
              {state.scope.allowedHosts.length > 0 && (
                <box flexDirection="column" paddingLeft={2}>
                  {state.scope.allowedHosts.map((h, i) => (
                    <text key={i} fg={colors.textMuted}>
                      • {h}
                    </text>
                  ))}
                </box>
              )}

              <box id={`field-${scopePortIndex}`}>
                <Input
                  label="Add Allowed Port"
                  description="Press Enter to add"
                  placeholder="443"
                  value={portInput}
                  onInput={setPortInput}
                  focused={focusedField === scopePortIndex}
                />
              </box>
              {state.scope.allowedPorts.length > 0 && (
                <box flexDirection="column" paddingLeft={2}>
                  {state.scope.allowedPorts.map((p, i) => (
                    <text key={i} fg={colors.textMuted}>
                      • {p}
                    </text>
                  ))}
                </box>
              )}

              <box id={`field-${scopeStrictIndex}`} flexDirection="row" gap={1}>
                <text
                  fg={
                    focusedField === scopeStrictIndex
                      ? colors.text
                      : colors.textMuted
                  }
                >
                  Strict Scope:
                </text>
                <text
                  fg={
                    state.scope.strictScope ? colors.primary : colors.textMuted
                  }
                >
                  {state.scope.strictScope ? "● Enabled" : "○ Disabled"}
                </text>
                {focusedField === scopeStrictIndex && (
                  <text fg={colors.textMuted}>{toggleHint}</text>
                )}
              </box>

              <box
                id={`field-${scopeSubdomainIndex}`}
                flexDirection="row"
                gap={1}
              >
                <text
                  fg={
                    focusedField === scopeSubdomainIndex
                      ? colors.primary
                      : colors.textMuted
                  }
                >
                  Enumerate Subdomains:
                </text>
                <text
                  fg={
                    state.scope.enumerateSubdomains
                      ? colors.primary
                      : colors.textMuted
                  }
                >
                  {state.scope.enumerateSubdomains ? "● Enabled" : "○ Disabled"}
                </text>
                {focusedField === scopeSubdomainIndex && (
                  <text fg={colors.textMuted}>{toggleHint}</text>
                )}
              </box>

              {/* Headers */}
              {sectionDivider("Headers")}

              <box id={`field-${headersModeIndex}`} flexDirection="row" gap={1}>
                <text
                  fg={
                    focusedField === headersModeIndex
                      ? colors.text
                      : colors.textMuted
                  }
                >
                  Headers:
                </text>
                <text fg={colors.primary}>
                  {capitalize(state.headers.mode)}
                </text>
                {focusedField === headersModeIndex && (
                  <text fg={colors.textMuted}>{cycleHint}</text>
                )}
              </box>

              {state.headers.mode === "custom" && (
                <>
                  <box id={`field-${headersNameIndex}`}>
                    <Input
                      label="Header Name"
                      placeholder="X-Custom-Header"
                      value={headerNameInput}
                      onInput={setHeaderNameInput}
                      focused={focusedField === headersNameIndex}
                    />
                  </box>
                  <box id={`field-${headersValueIndex}`}>
                    <Input
                      label="Header Value"
                      description="Press Enter to add"
                      placeholder="value"
                      value={headerValueInput}
                      onInput={setHeaderValueInput}
                      focused={focusedField === headersValueIndex}
                    />
                  </box>
                  {Object.keys(state.headers.customHeaders).length > 0 && (
                    <box flexDirection="column" paddingLeft={2}>
                      {Object.entries(state.headers.customHeaders).map(
                        ([k, v]) => (
                          <text key={k} fg={colors.textMuted}>
                            • {k}: {v}
                          </text>
                        ),
                      )}
                    </box>
                  )}
                </>
              )}
            </>
          )}
        </scrollbox>
      </DialogLayout>
    </Dialog>
  );
}
