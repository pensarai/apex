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
import {
  getAutoPopulatedHosts,
  getAutoPopulatedPorts,
} from "../../../util/url";
import { wrapThreatModelContent } from "../../../core/utils/prompt";

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
  const [hostInput, setHostInput] = useState("");
  const [portInput, setPortInput] = useState("");
  const [headerNameInput, setHeaderNameInput] = useState("");
  const [headerValueInput, setHeaderValueInput] = useState("");

  // Error state
  const [error, setError] = useState<string | null>(null);
  const [targetError, setTargetError] = useState<string | null>(null);

  // --- Field index computation ---
  // Fields:
  //   0: Target URL
  //   1: Source Code Access toggle
  //   2: Cwd path (only when source code access enabled)
  //   next: Prompt
  //   next: Threat Model
  //   next: Advanced toggle
  //   --- when advanced expanded ---
  //   next: Auth - Login URL
  //   next: Auth - Username
  //   next: Auth - Password
  //   next: Auth - Instructions
  //   next: Scope - Add Host
  //   next: Scope - Add Port
  //   next: Scope - Strict Scope toggle
  //   next: Scope - Enumerate Subdomains toggle
  //   next: Headers - Mode
  //   next: Headers - Header Name (only when custom)
  //   next: Headers - Header Value (only when custom)
  //   next: Model picker

  const cwdFieldIndex = state.sourceCodeAccess ? 2 : -1;
  const promptFieldIndex = state.sourceCodeAccess ? 3 : 2;
  const threatModelFieldIndex = promptFieldIndex + 1;
  const advancedToggleIndex = threatModelFieldIndex + 1;

  // Advanced sub-field indices (only valid when advancedExpanded)
  const authLoginUrlIndex = advancedToggleIndex + 1;
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
  const modelPickerIndex =
    state.headers.mode === "custom"
      ? headersModeIndex + 3
      : headersModeIndex + 1;

  const totalFields = advancedExpanded
    ? modelPickerIndex + 1
    : advancedToggleIndex + 1;

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

      // Operator guidance — combine threat model and prompt
      // Values are used as-is: if they came from CLI flags (initialPrompt/initialThreatModel),
      // they were already resolved by parseWebFlags. If the user typed them in the wizard,
      // they're plain text (the @file convention is for the CLI, not the wizard UI).
      const promptParts: string[] = [];
      if (state.threatModel.trim()) {
        const tm = state.threatModel.trim();
        // If already wrapped (from CLI --threat-model flag), use as-is.
        // Otherwise, wrap with the usage preamble so the agent gets guidance.
        promptParts.push(
          tm.includes("<threat-model>") ? tm : wrapThreatModelContent(tm),
        );
      }
      if (state.prompt.trim()) {
        promptParts.push(state.prompt.trim());
      }
      if (promptParts.length > 0) {
        sessionConfig.prompt = promptParts.join("\n\n");
      }

      onStartPentest([state.target], sessionConfig);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create session");
      setCreating(false);
    }
  }

  // Keyboard handling
  useKeyboard((key) => {
    // ESC - close
    if (key.name === "escape") {
      key.preventDefault();
      if (creating) return;
      onClose();
      return;
    }

    // Don't allow navigation while creating
    if (creating) return;

    // Enter — start pentest or add item
    if (key.name === "return") {
      key.preventDefault();

      // Add host
      if (
        focusedField === scopeHostIndex &&
        hostInput.trim() &&
        advancedExpanded
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
        focusedField === scopePortIndex &&
        portInput.trim() &&
        advancedExpanded
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
        // Move focus back to header name
        setFocusedField(headersNameIndex);
        return;
      }

      // Otherwise start pentest
      createSessionAndNavigate();
      return;
    }

    // Space — toggle source code access or advanced
    if (key.sequence === " ") {
      if (focusedField === 1) {
        key.preventDefault();
        setState((prev) => ({
          ...prev,
          sourceCodeAccess: !prev.sourceCodeAccess,
        }));
        return;
      }
      if (focusedField === advancedToggleIndex) {
        key.preventDefault();
        setAdvancedExpanded((prev) => !prev);
        return;
      }
      // Strict scope toggle
      if (focusedField === scopeStrictIndex && advancedExpanded) {
        key.preventDefault();
        setState((prev) => ({
          ...prev,
          scope: { ...prev.scope, strictScope: !prev.scope.strictScope },
        }));
        return;
      }
      // Enumerate subdomains toggle
      if (focusedField === scopeSubdomainIndex && advancedExpanded) {
        key.preventDefault();
        setState((prev) => ({
          ...prev,
          scope: {
            ...prev.scope,
            enumerateSubdomains: !prev.scope.enumerateSubdomains,
          },
        }));
        return;
      }
    }

    // Tab/Shift+Tab — navigate through flat field list
    if (key.name === "tab") {
      key.preventDefault();
      if (key.shift) {
        setFocusedField((prev) => Math.max(0, prev - 1));
      } else {
        setFocusedField((prev) => {
          const next = prev + 1;
          // If we're moving past the advanced toggle and it's collapsed, stop there
          if (prev === advancedToggleIndex && !advancedExpanded) {
            // Auto-expand advanced when tabbing past it
            setAdvancedExpanded(true);
            return next;
          }
          return Math.min(totalFields - 1, next);
        });
      }
      return;
    }

    // Arrow keys
    if (key.name === "up" || key.name === "down") {
      key.preventDefault();

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
      // Source code access toggle
      if (focusedField === 1) {
        setState((prev) => ({
          ...prev,
          sourceCodeAccess: !prev.sourceCodeAccess,
        }));
        return;
      }
      // Headers mode cycle
      if (focusedField === headersModeIndex && advancedExpanded) {
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
      // Model selection
      if (
        focusedField === modelPickerIndex &&
        advancedExpanded &&
        visibleModels.length > 0
      ) {
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

    // Model section: handle typing for search, backspace, left/right
    if (focusedField === modelPickerIndex && advancedExpanded) {
      // Backspace - remove last char from search
      if (key.name === "backspace") {
        key.preventDefault();
        setModelSearchQuery((prev) => prev.slice(0, -1));
        return;
      }
      // Left/Right - toggle provider expansion
      if (key.name === "left" || key.name === "right") {
        key.preventDefault();
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

  // Single-page wizard render
  return (
    <Dialog size="large" onClose={onClose}>
      <box flexDirection="column" width="100%" height="100%">
        <scrollbox
          style={{
            rootOptions: { flexGrow: 1, width: "100%" },
            contentOptions: {
              flexDirection: "column",
              gap: 1,
              paddingLeft: 4,
              paddingBottom: 1,
            },
          }}
          stickyScroll={false}
        >
          <box flexDirection="column">
            <text fg={colors.text}>
              Configure Web App Pentest - {modeLabel}
            </text>
            <text fg={colors.textMuted}>{modeDescription}</text>
            <text fg={colors.textMuted}>
              Model: {model.name} [{isModelUserSelected ? "user" : "default"}]
            </text>
          </box>

          {error && <text fg={colors.error}>Error: {error}</text>}

          {/* Target URL */}
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
          {targetError && <text fg={colors.error}>{targetError}</text>}

          {/* Source Code Access */}
          <box flexDirection="column" gap={1}>
            <box flexDirection="row" gap={1}>
              <text fg={focusedField === 1 ? colors.primary : colors.textMuted}>
                Source Code Access:
              </text>
              <text
                fg={state.sourceCodeAccess ? colors.primary : colors.textMuted}
              >
                {state.sourceCodeAccess ? "\u25CF Enabled" : "\u25CB Disabled"}
              </text>
              {focusedField === 1 && (
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
                focused={focusedField === cwdFieldIndex}
              />
            )}
          </box>

          {/* Prompt */}
          <Input
            label="Prompt"
            description="Guidance for the pentest agent (text or @filepath)"
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

          {/* Threat Model */}
          <Input
            label="Threat Model"
            description="Threat model file or text (text or @filepath)"
            placeholder="@./threat-model.md"
            value={state.threatModel}
            onInput={(v) => setState((prev) => ({ ...prev, threatModel: v }))}
            onPaste={(event) => {
              const cleaned = String(event.text).replace(/\r?\n/g, " ");
              setState((prev) => ({
                ...prev,
                threatModel: prev.threatModel + cleaned,
              }));
            }}
            focused={focusedField === threatModelFieldIndex}
          />

          {/* Advanced toggle */}
          <box flexDirection="row" gap={1}>
            <text
              fg={
                focusedField === advancedToggleIndex
                  ? colors.primary
                  : colors.textMuted
              }
            >
              {advancedExpanded ? "\u25BE" : "\u25B8"} Advanced
            </text>
            {focusedField === advancedToggleIndex && (
              <text fg={colors.textMuted}>(Space to toggle)</text>
            )}
          </box>

          {advancedExpanded && (
            <>
              {/* Auth fields */}
              <box flexDirection="column" gap={1} paddingLeft={2}>
                <text fg={colors.textMuted}>Authentication</text>
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
                <Input
                  label="Password"
                  placeholder="\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022"
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

              {/* Scope fields */}
              <box flexDirection="column" gap={1} paddingLeft={2}>
                <text fg={colors.textMuted}>Scope Constraints</text>
                <Input
                  label="Add Allowed Host"
                  description="Press Enter to add"
                  placeholder="example.com"
                  value={hostInput}
                  onInput={setHostInput}
                  focused={focusedField === scopeHostIndex}
                />
                {state.scope.allowedHosts.length > 0 && (
                  <box flexDirection="column" paddingLeft={2}>
                    {state.scope.allowedHosts.map((h, i) => (
                      <text key={i} fg={colors.textMuted}>
                        \u2022 {h}
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
                  focused={focusedField === scopePortIndex}
                />
                {state.scope.allowedPorts.length > 0 && (
                  <box flexDirection="column" paddingLeft={2}>
                    {state.scope.allowedPorts.map((p, i) => (
                      <text key={i} fg={colors.textMuted}>
                        \u2022 {p}
                      </text>
                    ))}
                  </box>
                )}
                <box flexDirection="row" gap={1}>
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
                      state.scope.strictScope
                        ? colors.primary
                        : colors.textMuted
                    }
                  >
                    {state.scope.strictScope
                      ? "\u25CF Enabled"
                      : "\u25CB Disabled"}
                  </text>
                  {focusedField === scopeStrictIndex && (
                    <text fg={colors.textMuted}>(\u2191/\u2193 to toggle)</text>
                  )}
                </box>
                <box flexDirection="row" gap={1}>
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
                    {state.scope.enumerateSubdomains
                      ? "\u25CF Enabled"
                      : "\u25CB Disabled"}
                  </text>
                  {focusedField === scopeSubdomainIndex && (
                    <text fg={colors.textMuted}>(\u2191/\u2193 to toggle)</text>
                  )}
                </box>
              </box>

              {/* Headers */}
              <box flexDirection="column" gap={1} paddingLeft={2}>
                <text fg={colors.textMuted}>Request Headers</text>
                <box flexDirection="column">
                  <text
                    fg={
                      state.headers.mode === "none"
                        ? colors.primary
                        : colors.textMuted
                    }
                  >
                    {state.headers.mode === "none" ? "\u25CF" : "\u25CB"} None
                  </text>
                  <text
                    fg={
                      state.headers.mode === "default"
                        ? colors.primary
                        : colors.textMuted
                    }
                  >
                    {state.headers.mode === "default" ? "\u25CF" : "\u25CB"}{" "}
                    Default (User-Agent: pensar-apex)
                  </text>
                  <text
                    fg={
                      state.headers.mode === "custom"
                        ? colors.primary
                        : colors.textMuted
                    }
                  >
                    {state.headers.mode === "custom" ? "\u25CF" : "\u25CB"}{" "}
                    Custom
                  </text>
                </box>
                {focusedField === headersModeIndex && (
                  <text fg={colors.textMuted}>Use \u2191/\u2193 to select</text>
                )}

                {state.headers.mode === "custom" && (
                  <box flexDirection="column" gap={1}>
                    <Input
                      label="Header Name"
                      placeholder="X-Custom-Header"
                      value={headerNameInput}
                      onInput={setHeaderNameInput}
                      focused={focusedField === headersNameIndex}
                    />
                    <Input
                      label="Header Value"
                      placeholder="value"
                      value={headerValueInput}
                      onInput={setHeaderValueInput}
                      focused={focusedField === headersValueIndex}
                    />
                    {Object.keys(state.headers.customHeaders).length > 0 && (
                      <box flexDirection="column">
                        {Object.entries(state.headers.customHeaders).map(
                          ([k, v]) => (
                            <text key={k} fg={colors.textMuted}>
                              \u2022 {k}: {v}
                            </text>
                          ),
                        )}
                      </box>
                    )}
                  </box>
                )}
              </box>

              {/* Model picker */}
              <box flexDirection="column" gap={0} paddingLeft={2}>
                <text fg={colors.textMuted}>
                  AI Model ({model.name}) [
                  {isModelUserSelected ? "user" : "default"}]
                </text>

                {focusedField === modelPickerIndex && (
                  <>
                    {/* Search input */}
                    {modelSearchQuery ? (
                      <text fg={colors.text}>Search: {modelSearchQuery}_</text>
                    ) : (
                      <text fg={colors.textMuted}>
                        Type to search models...
                      </text>
                    )}
                  </>
                )}

                {/* Provider groups */}
                {providerOrder.map((provider) => {
                  const models = groupedModels[provider];
                  if (!models || models.length === 0) return null;

                  const isExpanded = expandedProviders.has(provider);
                  const providerName = providerNames[provider] || provider;

                  return (
                    <box key={provider} flexDirection="column" gap={0}>
                      <text fg={isExpanded ? colors.text : colors.textMuted}>
                        {isExpanded ? "\u25BE" : "\u25B8"} {providerName} (
                        {models.length})
                      </text>

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
                                {isSelected ? "\u25CF" : "\u25CB"} {m.name}
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

                {focusedField === modelPickerIndex && (
                  <text fg={colors.textMuted}>
                    \u2191/\u2193 select \u2022 Type to search \u2022
                    \u2190/\u2192 collapse/expand
                  </text>
                )}
              </box>
            </>
          )}
        </scrollbox>
        <box marginTop={1} flexShrink={0} paddingLeft={4}>
          <DialogControls
            controls={[
              {
                key: "Enter",
                label: `Start Pentest (${modeLabel})`,
                variant: "primary",
              },
              { key: "Tab", label: "Navigate Fields" },
            ]}
          />
        </box>
      </box>
    </Dialog>
  );
}
