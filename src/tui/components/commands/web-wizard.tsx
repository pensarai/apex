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
import { type ModelInfo } from "../../../core/ai";
import { getAvailableModels } from "../../../core/providers/utils";

// Wizard step types
type WizardStep = "target" | "configure" | "creating";

// Wizard state interface
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

// Props for the WebWizard
interface WebWizardProps {
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
  initialHeadersMode?: 'none' | 'default' | 'custom';
  /** Pre-filled custom headers */
  initialCustomHeaders?: Record<string, string>;
  /** Pre-filled model ID */
  initialModel?: string;
}

// Color palette
const greenBullet = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);

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
  const route = useRoute();
  const config = useConfig();
  const { model, setModel, isModelUserSelected } = useAgent();

  // Available models based on configured API keys
  const [availableModels, setAvailableModels] = useState<ModelInfo[]>([]);
  const [selectedModelIndex, setSelectedModelIndex] = useState(0);

  // Model picker state
  const [modelSearchQuery, setModelSearchQuery] = useState("");
  const [expandedProviders, setExpandedProviders] = useState<Set<string>>(new Set(["anthropic"]));

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
      if (query && !m.name.toLowerCase().includes(query) && !m.id.toLowerCase().includes(query)) {
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
        const targetModel = models.find(m => m.id === initialModel);
        if (targetModel) {
          setModel(targetModel);
          const newIndex = models.findIndex(m => m.id === targetModel.id);
          if (newIndex >= 0) {
            setSelectedModelIndex(newIndex);
          }
          setExpandedProviders(new Set([targetModel.provider]));
          return;
        }
      }

      // Find current model in the list
      const currentIndex = models.findIndex(m => m.id === model.id);
      if (currentIndex >= 0) {
        setSelectedModelIndex(currentIndex);
      }
      // Auto-expand provider of current model
      if (models.length > 0) {
        const currentModel = models.find(m => m.id === model.id) || models[0];
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
    name: initialName || generateRandomName(),
    target: initialTarget || "",
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
    },
    headers: {
      mode: initialHeadersMode || "default",
      customHeaders: initialCustomHeaders || {},
    },
  }));

  // UI state for target step
  const [targetFocusedField, setTargetFocusedField] = useState(0); // 0=name, 1=target, 2=model (if multiple available)

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
      const sessionConfig: Session.SessionConfig = {
        // Set session type and mode for web app pentesting
        sessionType: 'web-app',
        mode: autoMode ? 'auto' : 'driver',
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

      const session = await Session.create({
        targets: [state.target],
        name: state.name,
        config: sessionConfig,
      });

      // Navigate to session route - SessionView will handle execution based on mode
      route.navigate({
        type: "session",
        sessionId: session.id,
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create session");
      setCurrentStep(initialTarget ? "configure" : "target");
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
        // If we have an initial target, go home instead of back to target step
        if (initialTarget) {
          route.navigate({ type: "base", path: "home" });
        } else {
          setCurrentStep("target");
          setFocusedSection(0);
          setFocusedField(0);
        }
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
          } else if (focusedSection < 3) {
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
        // Model selection - navigate through visible models
        if (focusedSection === 3 && visibleModels.length > 0) {
          const currentVisibleIndex = visibleModels.findIndex(m => m.id === model.id);
          const newVisibleIndex = key.name === "up"
            ? Math.max(0, currentVisibleIndex - 1)
            : Math.min(visibleModels.length - 1, currentVisibleIndex + 1);
          const newModel = visibleModels[newVisibleIndex];
          if (newModel) {
            setModel(newModel);
            const newGlobalIndex = availableModels.findIndex(m => m.id === newModel.id);
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
          setModelSearchQuery(prev => prev.slice(0, -1));
          return;
        }
        // Escape - clear search
        if (key.name === "escape" && modelSearchQuery) {
          setModelSearchQuery("");
          return;
        }
        // Left/Right - toggle provider expansion
        if (key.name === "left" || key.name === "right") {
          // Find which provider the current model belongs to
          const currentProvider = model.provider;
          if (key.name === "left") {
            setExpandedProviders(prev => {
              const next = new Set(prev);
              next.delete(currentProvider);
              return next;
            });
          } else {
            setExpandedProviders(prev => new Set([...prev, currentProvider]));
          }
          return;
        }
        // Tab in model section - toggle next provider expansion
        if (key.name === "tab" && !key.shift) {
          const availableProviders = providerOrder.filter(p => groupedModels[p]?.length > 0);
          if (availableProviders.length > 0) {
            // Find next provider to toggle
            const currentExpanded = [...expandedProviders];
            const nextToExpand = availableProviders.find(p => !expandedProviders.has(p));
            if (nextToExpand) {
              setExpandedProviders(prev => new Set([...prev, nextToExpand]));
            } else {
              // All expanded, go to next section
              setFocusedSection(0);
              setFocusedField(0);
            }
            return;
          }
        }
        // Printable character - add to search
        if (key.sequence && key.sequence.length === 1 && /[a-zA-Z0-9\-_.]/.test(key.sequence)) {
          setModelSearchQuery(prev => prev + key.sequence);
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
      case 0: return 4; // Auth
      case 1: return 3; // Scope
      case 2: return state.headers.mode === "custom" ? 3 : 1; // Headers
      case 3: return 1; // Model
      default: return 1;
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
        <text fg={dimText}>Mode: {modeLabel}</text>
      </box>
    );
  }

  // Render target step
  if (currentStep === "target") {
    return (
      <box width="100%" flexDirection="column" gap={2} paddingLeft={4}>
        <text fg={creamText}>Configure Web App Pentest</text>
        <text fg={dimText}>{modeDescription}</text>
        <text fg={dimText}>
          Model: {model.name} [{isModelUserSelected ? "user" : "default"}]
        </text>

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
        <text fg={creamText}>Configure Web App Pentest - {modeLabel}</text>
        <text fg={dimText}>Target: {state.target}</text>
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

      {/* Model Section */}
      <box flexDirection="column" gap={1}>
        <text>
          <span fg={greenBullet}>█ </span>
          <span fg={focusedSection === 3 ? creamText : dimText}>AI Model</span>
          <span fg={dimText}> ({model.name})</span>
          <span fg={dimText}> [{isModelUserSelected ? "user" : "default"}]</span>
        </text>
        {focusedSection === 3 && (
          <box flexDirection="column" gap={0} paddingLeft={2}>
            {/* Search input */}
            {modelSearchQuery && (
              <text fg={creamText}>Search: {modelSearchQuery}_</text>
            )}
            {!modelSearchQuery && (
              <text fg={dimText}>Type to search models...</text>
            )}

            {/* Provider groups */}
            {providerOrder.map(provider => {
              const models = groupedModels[provider];
              if (!models || models.length === 0) return null;

              const isExpanded = expandedProviders.has(provider);
              const providerName = providerNames[provider] || provider;

              return (
                <box key={provider} flexDirection="column" gap={0}>
                  {/* Provider header */}
                  <text
                    fg={isExpanded ? creamText : dimText}
                  >
                    {isExpanded ? "▾" : "▸"} {providerName} ({models.length})
                  </text>

                  {/* Models list (when expanded) */}
                  {isExpanded && (
                    <box flexDirection="column" gap={0} paddingLeft={2}>
                      {models.map((m) => {
                        const isSelected = m.id === model.id;
                        const isDefault = m.id === "claude-haiku-4-5" || m.id === "gpt-4o-mini";
                        return (
                          <text key={m.id} fg={isSelected ? greenBullet : dimText}>
                            {isSelected ? "●" : "○"} {m.name}
                            {isDefault && !isModelUserSelected && isSelected ? " [default]" : ""}
                          </text>
                        );
                      })}
                    </box>
                  )}
                </box>
              );
            })}

            {/* Help text */}
            <text fg={dimText}>↑/↓ select • Type to search • ←/→ collapse/expand</text>
          </box>
        )}
      </box>

      <box flexDirection="column" gap={0} marginTop={1}>
        <text>
          <span fg={greenBullet}>█ </span>
          <span fg={dimText}>Press </span>
          <span fg={creamText}>[Enter]</span>
          <span fg={dimText}> to start pentest ({modeLabel})</span>
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
