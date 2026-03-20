import { useState, useEffect, useMemo } from "react";
import { useKeyboard } from "@opentui/react";
import Input from "../input";
import { useConfig } from "../../context/config";
import { useAgent } from "../../context/agent";
import type { SessionConfig } from "../../../core/session";
import { SpinnerDots } from "../sprites";
import { type ModelInfo } from "../../../core/ai";
import { getAvailableModels } from "../../../core/providers/utils";
import { useTheme } from "../../theme";
import { Dialog } from "../../context/dialog";
import { DialogControls } from "../shared/dialog-controls";

// Wizard step types
type WizardStep = "target" | "configure" | "creating";

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
}: WebWizardProps) {
  const { colors } = useTheme();
  const config = useConfig();
  const { model, setModel, isModelUserSelected } = useAgent();

  // Available models based on configured API keys
  const [availableModels, setAvailableModels] = useState<ModelInfo[]>([]);
  const [selectedModelIndex, setSelectedModelIndex] = useState(0);

  // Model picker state
  const [modelSearchQuery, setModelSearchQuery] = useState("");
  const [expandedProviders, setExpandedProviders] = useState<Set<string>>(
    new Set(["anthropic"]),
  );

  // Provider display names
  const providerNames: Record<string, string> = {
    anthropic: "Claude",
    openai: "OpenAI",
    openrouter: "OpenRouter",
    bedrock: "Bedrock",
  };

  // Provider order
  const providerOrder = ["anthropic", "openai", "openrouter", "bedrock"];

  // Group models by provider and filter by search
  const groupedModels = useMemo(() => {
    const groups: Record<string, ModelInfo[]> = {};
    const query = modelSearchQuery.toLowerCase().trim();

    for (const m of availableModels) {
      // Fuzzy match: check if query matches model name or id
      if (
        query &&
        !m.name.toLowerCase().includes(query) &&
        !m.id.toLowerCase().includes(query)
      ) {
        continue;
      }
      if (!groups[m.provider]) {
        groups[m.provider] = [];
      }
      groups[m.provider].push(m);
    }
    return groups;
  }, [availableModels, modelSearchQuery]);

  // Flat list of visible models for keyboard navigation
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

  // Load available models when config changes
  useEffect(() => {
    if (config.data) {
      const models = getAvailableModels(config.data);
      setAvailableModels(models);

      // If initialModel was provided, try to set it
      if (initialModel) {
        const targetModel = models.find((m) => m.id === initialModel);
        if (targetModel) {
          setModel(targetModel, false);
          const newIndex = models.findIndex((m) => m.id === targetModel.id);
          if (newIndex >= 0) {
            setSelectedModelIndex(newIndex);
          }
          setExpandedProviders(new Set([targetModel.provider]));
          return;
        }
      }

      // Find current model in the list
      const currentIndex = models.findIndex((m) => m.id === model.id);
      if (currentIndex >= 0) {
        setSelectedModelIndex(currentIndex);
      }
      // Auto-expand provider of current model
      if (models.length > 0) {
        const currentModel = models.find((m) => m.id === model.id) || models[0];
        if (currentModel) {
          setExpandedProviders(new Set([currentModel.provider]));
        }
      }
    }
  }, [config.data, model.id, initialModel]);

  // Determine initial step based on whether target was provided
  const initialStep: WizardStep = initialTarget ? "configure" : "target";

  // Wizard state
  const [currentStep, setCurrentStep] = useState<WizardStep>(initialStep);
  const [state, setState] = useState<WizardState>(() => ({
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

  // UI state for target step
  const [targetFocusedField, setTargetFocusedField] = useState(0); // 0=target, 1=source code access, 2=cwd (if enabled)

  // UI state for configure step
  const [focusedSection, setFocusedSection] = useState(0); // 0=auth, 1=scope, 2=headers
  const [focusedField, setFocusedField] = useState(0);
  const [hostInput, setHostInput] = useState("");
  const [portInput, setPortInput] = useState("");
  const [headerNameInput, setHeaderNameInput] = useState("");
  const [headerValueInput, setHeaderValueInput] = useState("");

  // Error state
  const [error, setError] = useState<string | null>(null);
  const [targetError, setTargetError] = useState<string | null>(null);

  // Create session and navigate to session route
  async function createSessionAndNavigate() {
    if (!state.target.trim()) return;

    setCurrentStep("creating");
    setError(null);

    try {
      // Build session config
      const sessionConfig: SessionConfig = {
        // Set session type and mode for web app pentesting
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

      onStartPentest([state.target], sessionConfig);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create session");
      setCurrentStep(initialTarget ? "configure" : "target");
    }
  }

  // Keyboard handling
  useKeyboard((key) => {
    // ESC - Go back or close
    if (key.name === "escape") {
      key.preventDefault();
      if (currentStep === "creating") {
        // Can't cancel while creating
        return;
      }
      if (currentStep === "configure") {
        // If we have an initial target, close dialog instead of back to target step
        if (initialTarget) {
          onClose();
        } else {
          setCurrentStep("target");
          setFocusedSection(0);
          setFocusedField(0);
        }
        return;
      }
      onClose();
      return;
    }

    // Don't allow navigation while creating
    if (currentStep === "creating") return;

    // Target step: Enter to start, Tab to configure options
    if (currentStep === "target") {
      const maxTargetField = state.sourceCodeAccess ? 2 : 1; // 0=target, 1=toggle, 2=cwd (if enabled)
      // Tab - go directly to configure step when target is filled
      if (key.name === "tab" && !key.shift) {
        key.preventDefault();
        if (state.target.trim()) {
          setTargetError(null);
          setCurrentStep("configure");
        } else {
          setTargetError("Target URL is required");
        }
        return;
      }
      // Shift+Tab - navigate backwards through fields
      if (key.name === "tab" && key.shift) {
        key.preventDefault();
        setTargetFocusedField((prev) => Math.max(0, prev - 1));
        return;
      }
      // Down arrow - navigate to next field
      if (key.name === "down") {
        key.preventDefault();
        if (targetFocusedField < maxTargetField) {
          setTargetFocusedField((prev) => prev + 1);
        }
        return;
      }
      // Up arrow - navigate to previous field
      if (key.name === "up") {
        key.preventDefault();
        if (targetFocusedField > 0) {
          setTargetFocusedField((prev) => prev - 1);
        }
        return;
      }
      // Space - toggle source code access when on that field
      if (key.sequence === " " && targetFocusedField === 1) {
        key.preventDefault();
        setState((prev) => ({
          ...prev,
          sourceCodeAccess: !prev.sourceCodeAccess,
        }));
        return;
      }
      // Enter to start if target is filled
      if (key.name === "return" && state.target.trim()) {
        key.preventDefault();
        createSessionAndNavigate();
        return;
      }
      return;
    }

    // Configure step keyboard handling
    if (currentStep === "configure") {
      // Enter to create session
      if (key.name === "return") {
        key.preventDefault();
        // Check if we should add an item instead of starting
        if (focusedSection === 1 && focusedField === 0 && hostInput.trim()) {
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
        if (focusedSection === 1 && focusedField === 1 && portInput.trim()) {
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
        if (
          focusedSection === 2 &&
          state.headers.mode === "custom" &&
          focusedField === 2 &&
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
        // Otherwise create session
        createSessionAndNavigate();
        return;
      }

      // Tab navigation between sections and fields
      if (key.name === "tab") {
        key.preventDefault();
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
          } else if (focusedSection < 3) {
            setFocusedSection(focusedSection + 1);
            setFocusedField(0);
          }
        }
        return;
      }

      // Arrow keys for toggles
      if (key.name === "up" || key.name === "down") {
        key.preventDefault();
        if (focusedSection === 1 && focusedField === 2) {
          setState((prev) => ({
            ...prev,
            scope: { ...prev.scope, strictScope: !prev.scope.strictScope },
          }));
          return;
        }
        if (focusedSection === 1 && focusedField === 3) {
          setState((prev) => ({
            ...prev,
            scope: {
              ...prev.scope,
              enumerateSubdomains: !prev.scope.enumerateSubdomains,
            },
          }));
          return;
        }
        if (focusedSection === 2 && focusedField === 0) {
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
        // Model selection - navigate through visible models
        if (focusedSection === 3 && visibleModels.length > 0) {
          const currentVisibleIndex = visibleModels.findIndex(
            (m) => m.id === model.id,
          );
          const newVisibleIndex =
            key.name === "up"
              ? Math.max(0, currentVisibleIndex - 1)
              : Math.min(visibleModels.length - 1, currentVisibleIndex + 1);
          const newModel = visibleModels[newVisibleIndex];
          if (newModel) {
            setModel(newModel);
            const newGlobalIndex = availableModels.findIndex(
              (m) => m.id === newModel.id,
            );
            if (newGlobalIndex >= 0) {
              setSelectedModelIndex(newGlobalIndex);
            }
          }
          return;
        }
      }

      // Model section: handle typing for search, backspace, escape
      if (focusedSection === 3) {
        // Backspace - remove last char from search
        if (key.name === "backspace") {
          key.preventDefault();
          setModelSearchQuery((prev) => prev.slice(0, -1));
          return;
        }
        // Escape - clear search
        if (key.name === "escape" && modelSearchQuery) {
          setModelSearchQuery("");
          return;
        }
        // Left/Right - toggle provider expansion
        if (key.name === "left" || key.name === "right") {
          key.preventDefault();
          // Find which provider the current model belongs to
          const currentProvider = model.provider;
          if (key.name === "left") {
            setExpandedProviders((prev) => {
              const next = new Set(prev);
              next.delete(currentProvider);
              return next;
            });
          } else {
            setExpandedProviders((prev) => new Set([...prev, currentProvider]));
          }
          return;
        }
        // Tab in model section - toggle next provider expansion
        if (key.name === "tab" && !key.shift) {
          key.preventDefault();
          const availableProviders = providerOrder.filter(
            (p) => groupedModels[p]?.length > 0,
          );
          if (availableProviders.length > 0) {
            // Find next provider to toggle
            const currentExpanded = [...expandedProviders];
            const nextToExpand = availableProviders.find(
              (p) => !expandedProviders.has(p),
            );
            if (nextToExpand) {
              setExpandedProviders((prev) => new Set([...prev, nextToExpand]));
            } else {
              // All expanded, go to next section
              setFocusedSection(0);
              setFocusedField(0);
            }
            return;
          }
        }
        // Printable character - add to search
        if (
          key.sequence &&
          key.sequence.length === 1 &&
          /[a-zA-Z0-9\-_.]/.test(key.sequence)
        ) {
          key.preventDefault();
          setModelSearchQuery((prev) => prev + key.sequence);
          // Auto-expand all providers when searching
          if (!modelSearchQuery) {
            setExpandedProviders(new Set(providerOrder));
          }
          return;
        }
      }
    }
  });

  function getMaxFieldsForSection(section: number): number {
    switch (section) {
      case 0:
        return 4; // Auth
      case 1:
        return 4; // Scope (host, port, strictScope, enumerateSubdomains)
      case 2:
        return state.headers.mode === "custom" ? 3 : 1; // Headers
      case 3:
        return 1; // Model
      default:
        return 1;
    }
  }

  // Get mode label for display
  const modeLabel = autoMode ? "Auto Mode" : "Driver Mode";
  const modeDescription = autoMode
    ? "Automated pentesting - agents run autonomously"
    : "Manual orchestration - you direct the agents";

  // Render creating state
  if (currentStep === "creating") {
    return (
      <Dialog size="large" onClose={onClose}>
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
      </Dialog>
    );
  }

  // Render target step
  if (currentStep === "target") {
    return (
      <Dialog size="large" onClose={onClose}>
        <box
          width="100%"
          flexDirection="column"
          gap={2}
          paddingLeft={4}
          paddingBottom={1}
        >
          <text fg={colors.text}>Configure Web App Pentest</text>
          <text fg={colors.textMuted}>{modeDescription}</text>
          <text fg={colors.textMuted}>
            Model: {model.name} [{isModelUserSelected ? "user" : "default"}]
          </text>

          {error && <text fg={colors.error}>Error: {error}</text>}

          <Input
            label="Target URL"
            description="e.g., https://example.com"
            placeholder="https://example.com"
            value={state.target}
            onInput={(v) => {
              setTargetError(null);
              setState((prev) => ({ ...prev, target: v }));
            }}
            onSubmit={() => {
              if (state.target.trim()) {
                setTargetError(null);
                setCurrentStep("configure");
              } else {
                setTargetError("Target URL is required");
              }
            }}
            focused={targetFocusedField === 0}
          />
          {targetError && <text fg={colors.error}>{targetError}</text>}

          <box flexDirection="column" gap={1}>
            <box flexDirection="row" gap={1}>
              <text
                fg={
                  targetFocusedField === 1 ? colors.primary : colors.textMuted
                }
              >
                Source Code Access:
              </text>
              <text
                fg={state.sourceCodeAccess ? colors.primary : colors.textMuted}
              >
                {state.sourceCodeAccess ? "● Enabled" : "○ Disabled"}
              </text>
              {targetFocusedField === 1 && (
                <text fg={colors.textMuted}>(Space to toggle)</text>
              )}
            </box>
            {state.sourceCodeAccess && (
              <Input
                label="Codebase Path"
                description="Path to the source code directory"
                placeholder={process.cwd()}
                value={state.cwd}
                onInput={(v) => setState((prev) => ({ ...prev, cwd: v }))}
                focused={targetFocusedField === 2}
              />
            )}
          </box>

          <box marginTop={1}>
            <DialogControls
              controls={[
                {
                  key: "Enter",
                  label: "Start Immediately",
                  variant: "primary",
                },
                { key: "Tab", label: "Configure Options" },
                { key: "Esc", label: "Cancel" },
              ]}
            />
          </box>
        </box>
      </Dialog>
    );
  }

  // Render configure step
  return (
    <Dialog size="large" onClose={onClose}>
      <box
        width="100%"
        flexDirection="column"
        gap={2}
        paddingLeft={4}
        paddingBottom={1}
      >
        <box flexDirection="column">
          <text fg={colors.text}>Configure Web App Pentest - {modeLabel}</text>
          <text fg={colors.textMuted}>Target: {state.target}</text>
          <text fg={colors.textMuted}>
            All fields are optional - configure only what you need
          </text>
        </box>

        {/* Auth Section */}
        <box flexDirection="column" gap={1}>
          <text>
            <span fg={colors.primary}>█ </span>
            <span fg={focusedSection === 0 ? colors.text : colors.textMuted}>
              Authentication
            </span>
          </text>
          {focusedSection === 0 && (
            <box flexDirection="column" gap={1} paddingLeft={2}>
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
                focused={focusedField === 0}
              />
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
                focused={focusedField === 1}
              />
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
                focused={focusedField === 2}
              />
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
                focused={focusedField === 3}
              />
            </box>
          )}
        </box>

        {/* Scope Section */}
        <box flexDirection="column" gap={1}>
          <text>
            <span fg={colors.primary}>█ </span>
            <span fg={focusedSection === 1 ? colors.text : colors.textMuted}>
              Scope Constraints
            </span>
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
                    <text key={i} fg={colors.textMuted}>
                      • {h}
                    </text>
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
                    <text key={i} fg={colors.textMuted}>
                      • {p}
                    </text>
                  ))}
                </box>
              )}
              <box flexDirection="row" gap={1}>
                <text fg={focusedField === 2 ? colors.text : colors.textMuted}>
                  Strict Scope:
                </text>
                <text
                  fg={
                    state.scope.strictScope ? colors.primary : colors.textMuted
                  }
                >
                  {state.scope.strictScope ? "● Enabled" : "○ Disabled"}
                </text>
                {focusedField === 2 && (
                  <text fg={colors.textMuted}>(↑/↓ to toggle)</text>
                )}
              </box>
              <box flexDirection="row" gap={1}>
                <text
                  fg={focusedField === 3 ? colors.primary : colors.textMuted}
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
                {focusedField === 3 && (
                  <text fg={colors.textMuted}>(↑/↓ to toggle)</text>
                )}
              </box>
            </box>
          )}
        </box>

        {/* Headers Section */}
        <box flexDirection="column" gap={1}>
          <text>
            <span fg={colors.primary}>█ </span>
            <span fg={focusedSection === 2 ? colors.text : colors.textMuted}>
              Request Headers
            </span>
          </text>
          {focusedSection === 2 && (
            <box flexDirection="column" gap={1} paddingLeft={2}>
              <box flexDirection="column">
                <text
                  fg={
                    state.headers.mode === "none"
                      ? colors.primary
                      : colors.textMuted
                  }
                >
                  {state.headers.mode === "none" ? "●" : "○"} None
                </text>
                <text
                  fg={
                    state.headers.mode === "default"
                      ? colors.primary
                      : colors.textMuted
                  }
                >
                  {state.headers.mode === "default" ? "●" : "○"} Default
                  (User-Agent: pensar-apex)
                </text>
                <text
                  fg={
                    state.headers.mode === "custom"
                      ? colors.primary
                      : colors.textMuted
                  }
                >
                  {state.headers.mode === "custom" ? "●" : "○"} Custom
                </text>
              </box>
              {focusedField === 0 && (
                <text fg={colors.textMuted}>Use ↑/↓ to select</text>
              )}

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
                      {Object.entries(state.headers.customHeaders).map(
                        ([k, v]) => (
                          <text key={k} fg={colors.textMuted}>
                            • {k}: {v}
                          </text>
                        ),
                      )}
                    </box>
                  )}
                </box>
              )}
            </box>
          )}
        </box>

        {/* Model Section */}
        <box flexDirection="column" gap={1}>
          <text>
            <span fg={colors.primary}>█ </span>
            <span fg={focusedSection === 3 ? colors.text : colors.textMuted}>
              AI Model
            </span>
            <span fg={colors.textMuted}> ({model.name})</span>
            <span fg={colors.textMuted}>
              {" "}
              [{isModelUserSelected ? "user" : "default"}]
            </span>
          </text>
          {focusedSection === 3 && (
            <box flexDirection="column" gap={0} paddingLeft={2}>
              {/* Search input */}
              {modelSearchQuery && (
                <text fg={colors.text}>Search: {modelSearchQuery}_</text>
              )}
              {!modelSearchQuery && (
                <text fg={colors.textMuted}>Type to search models...</text>
              )}

              {/* Provider groups */}
              {providerOrder.map((provider) => {
                const models = groupedModels[provider];
                if (!models || models.length === 0) return null;

                const isExpanded = expandedProviders.has(provider);
                const providerName = providerNames[provider] || provider;

                return (
                  <box key={provider} flexDirection="column" gap={0}>
                    {/* Provider header */}
                    <text fg={isExpanded ? colors.text : colors.textMuted}>
                      {isExpanded ? "▾" : "▸"} {providerName} ({models.length})
                    </text>

                    {/* Models list (when expanded) */}
                    {isExpanded && (
                      <box flexDirection="column" gap={0} paddingLeft={2}>
                        {models.map((m) => {
                          const isSelected = m.id === model.id;
                          const isDefault =
                            m.id === "claude-haiku-4-5" ||
                            m.id === "gpt-4o-mini";
                          return (
                            <text
                              key={m.id}
                              fg={
                                isSelected ? colors.primary : colors.textMuted
                              }
                            >
                              {isSelected ? "●" : "○"} {m.name}
                              {isDefault && !isModelUserSelected && isSelected
                                ? " [default]"
                                : ""}
                            </text>
                          );
                        })}
                      </box>
                    )}
                  </box>
                );
              })}

              {/* Help text */}
              <text fg={colors.textMuted}>
                ↑/↓ select • Type to search • ←/→ collapse/expand
              </text>
            </box>
          )}
        </box>

        <box marginTop={1}>
          <DialogControls
            controls={[
              {
                key: "Enter",
                label: `Start Pentest (${modeLabel})`,
                variant: "primary",
              },
              { key: "Tab", label: "Navigate Fields" },
              { key: "Esc", label: "Go Back" },
            ]}
          />
        </box>
      </box>
    </Dialog>
  );
}
