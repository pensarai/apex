import { useState, useEffect, useMemo, useRef } from "react";
import { useKeyboard } from "@opentui/react";
import { ScrollBoxRenderable } from "@opentui/core";
import Input from "../input";
import { useConfig } from "../../context/config";
import { useAgent } from "../../context/agent";
import type { SessionConfig } from "../../../core/session";
import { SpinnerDots } from "../sprites";
import { type ModelInfo } from "../../../core/ai";
import { getAvailableModels } from "../../../core/providers/utils";
import { useTheme } from "../../theme";
import { Dialog } from "../../context/dialog";
import { scrollToChild } from "../../utils/scroll";

// Navigation item for flat keyboard navigation
interface NavItem {
  id: string;
  type: "input" | "toggle" | "section" | "radio" | "provider" | "model";
  key: string;
}

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

const providerNames: Record<string, string> = {
  anthropic: "Claude",
  openai: "OpenAI",
  openrouter: "OpenRouter",
  bedrock: "Bedrock",
};

const providerOrder = ["anthropic", "openai", "openrouter", "bedrock"];

export default function WebWizard({
  onClose,
  onStartPentest,
  initialTarget,
  autoMode = false,
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
  const scrollBoxRef = useRef<ScrollBoxRenderable | null>(null);

  // Model state
  const [availableModels, setAvailableModels] = useState<ModelInfo[]>([]);
  const [expandedProviders, setExpandedProviders] = useState<Set<string>>(
    new Set(["anthropic"]),
  );

  const groupedModels = useMemo(() => {
    const groups: Record<string, ModelInfo[]> = {};
    for (const m of availableModels) {
      if (!groups[m.provider]) groups[m.provider] = [];
      groups[m.provider].push(m);
    }
    return groups;
  }, [availableModels]);

  // Load available models when config changes
  useEffect(() => {
    if (config.data) {
      const models = getAvailableModels(config.data);
      setAvailableModels(models);

      if (initialModel) {
        const targetModel = models.find((m) => m.id === initialModel);
        if (targetModel) {
          setModel(targetModel, false);
          setExpandedProviders(new Set([targetModel.provider]));
          return;
        }
      }

      if (models.length > 0) {
        const currentModel = models.find((m) => m.id === model.id) || models[0];
        if (currentModel) {
          setExpandedProviders(new Set([currentModel.provider]));
        }
      }
    }
  }, [config.data, model.id, initialModel]);

  // UI state
  const [isCreating, setIsCreating] = useState(false);

  // Form state
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

  // Section expansion state
  const [advancedExpanded, setAdvancedExpanded] = useState(false);
  const [authExpanded, setAuthExpanded] = useState(false);
  const [scopeExpanded, setScopeExpanded] = useState(false);
  const [headersExpanded, setHeadersExpanded] = useState(false);
  const [modelSectionExpanded, setModelSectionExpanded] = useState(false);

  // Navigation state
  const [focusedIndex, setFocusedIndex] = useState(0);

  // Input state for list-adder fields
  const [hostInput, setHostInput] = useState("");
  const [portInput, setPortInput] = useState("");
  const [headerNameInput, setHeaderNameInput] = useState("");
  const [headerValueInput, setHeaderValueInput] = useState("");

  // Error state
  const [error, setError] = useState<string | null>(null);
  const [targetError, setTargetError] = useState<string | null>(null);

  // Build flat navigation items list
  const navItems = useMemo(() => {
    const items: NavItem[] = [];

    items.push({ id: "field-target", type: "input", key: "target" });
    items.push({
      id: "field-sourceCodeAccess",
      type: "toggle",
      key: "sourceCodeAccess",
    });
    if (state.sourceCodeAccess) {
      items.push({ id: "field-cwd", type: "input", key: "cwd" });
    }

    items.push({ id: "section-advanced", type: "section", key: "advanced" });

    if (advancedExpanded) {
      items.push({ id: "section-auth", type: "section", key: "auth" });
      if (authExpanded) {
        items.push({ id: "field-loginUrl", type: "input", key: "loginUrl" });
        items.push({ id: "field-username", type: "input", key: "username" });
        items.push({ id: "field-password", type: "input", key: "password" });
        items.push({
          id: "field-instructions",
          type: "input",
          key: "instructions",
        });
      }

      items.push({ id: "section-scope", type: "section", key: "scope" });
      if (scopeExpanded) {
        items.push({ id: "field-host", type: "input", key: "host" });
        items.push({ id: "field-port", type: "input", key: "port" });
        items.push({
          id: "field-strictScope",
          type: "toggle",
          key: "strictScope",
        });
        items.push({
          id: "field-enumerateSubdomains",
          type: "toggle",
          key: "enumerateSubdomains",
        });
      }

      items.push({ id: "section-headers", type: "section", key: "headers" });
      if (headersExpanded) {
        items.push({
          id: "field-headersMode",
          type: "radio",
          key: "headersMode",
        });
        if (state.headers.mode === "custom") {
          items.push({
            id: "field-headerName",
            type: "input",
            key: "headerName",
          });
          items.push({
            id: "field-headerValue",
            type: "input",
            key: "headerValue",
          });
        }
      }

      items.push({ id: "section-model", type: "section", key: "model" });
      if (modelSectionExpanded) {
        for (const provider of providerOrder) {
          const models = groupedModels[provider];
          if (!models || models.length === 0) continue;
          items.push({
            id: `provider-${provider}`,
            type: "provider",
            key: provider,
          });
          if (expandedProviders.has(provider)) {
            for (const m of models) {
              items.push({ id: `model-${m.id}`, type: "model", key: m.id });
            }
          }
        }
      }
    }

    return items;
  }, [
    state.sourceCodeAccess,
    state.headers.mode,
    advancedExpanded,
    authExpanded,
    scopeExpanded,
    headersExpanded,
    modelSectionExpanded,
    groupedModels,
    expandedProviders,
  ]);

  // Clamp focused index when items change
  useEffect(() => {
    setFocusedIndex((prev) => Math.min(prev, Math.max(0, navItems.length - 1)));
  }, [navItems.length]);

  // Scroll to focused item
  useEffect(() => {
    const item = navItems[focusedIndex];
    if (item) scrollToChild(scrollBoxRef.current, item.id);
  }, [focusedIndex, navItems]);

  const focusedItem = navItems[focusedIndex];

  // Section helpers
  function toggleSection(key: string) {
    switch (key) {
      case "advanced":
        setAdvancedExpanded((p) => !p);
        break;
      case "auth":
        setAuthExpanded((p) => !p);
        break;
      case "scope":
        setScopeExpanded((p) => !p);
        break;
      case "headers":
        setHeadersExpanded((p) => !p);
        break;
      case "model":
        setModelSectionExpanded((p) => !p);
        break;
    }
  }

  function expandSection(key: string) {
    switch (key) {
      case "advanced":
        setAdvancedExpanded(true);
        break;
      case "auth":
        setAuthExpanded(true);
        break;
      case "scope":
        setScopeExpanded(true);
        break;
      case "headers":
        setHeadersExpanded(true);
        break;
      case "model":
        setModelSectionExpanded(true);
        break;
    }
  }

  function collapseSection(key: string) {
    switch (key) {
      case "advanced":
        setAdvancedExpanded(false);
        break;
      case "auth":
        setAuthExpanded(false);
        break;
      case "scope":
        setScopeExpanded(false);
        break;
      case "headers":
        setHeadersExpanded(false);
        break;
      case "model":
        setModelSectionExpanded(false);
        break;
    }
  }

  // Toggle value handler
  function handleToggle(key: string) {
    switch (key) {
      case "sourceCodeAccess":
        setState((prev) => ({
          ...prev,
          sourceCodeAccess: !prev.sourceCodeAccess,
        }));
        break;
      case "strictScope":
        setState((prev) => ({
          ...prev,
          scope: { ...prev.scope, strictScope: !prev.scope.strictScope },
        }));
        break;
      case "enumerateSubdomains":
        setState((prev) => ({
          ...prev,
          scope: {
            ...prev.scope,
            enumerateSubdomains: !prev.scope.enumerateSubdomains,
          },
        }));
        break;
    }
  }

  // Create session and navigate to pentest
  async function createSessionAndNavigate() {
    if (!state.target.trim()) return;

    setIsCreating(true);
    setError(null);

    try {
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
        sessionConfig.cwd = state.cwd.trim();
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
      setIsCreating(false);
    }
  }

  // Navigate to a new index, auto-selecting model if applicable
  function navigateTo(newIndex: number) {
    setFocusedIndex(newIndex);
    const newItem = navItems[newIndex];
    if (newItem?.type === "model") {
      const modelInfo = availableModels.find((m) => m.id === newItem.key);
      if (modelInfo) setModel(modelInfo);
    }
  }

  // Keyboard handler
  useKeyboard((key) => {
    if (isCreating) return;

    // ESC - close dialog
    if (key.name === "escape") {
      key.preventDefault();
      onClose();
      return;
    }

    // Up/Down - navigate between items
    if (key.name === "up" || key.name === "down") {
      key.preventDefault();
      const newIndex =
        key.name === "up"
          ? Math.max(0, focusedIndex - 1)
          : Math.min(navItems.length - 1, focusedIndex + 1);
      navigateTo(newIndex);
      return;
    }

    // Tab/Shift+Tab - navigate (same as Down/Up)
    if (key.name === "tab") {
      key.preventDefault();
      const newIndex = key.shift
        ? Math.max(0, focusedIndex - 1)
        : Math.min(navItems.length - 1, focusedIndex + 1);
      navigateTo(newIndex);
      return;
    }

    // Space - toggle/cycle for non-input items
    if (key.sequence === " ") {
      if (focusedItem?.type === "toggle") {
        key.preventDefault();
        handleToggle(focusedItem.key);
        return;
      }
      if (focusedItem?.type === "section") {
        key.preventDefault();
        toggleSection(focusedItem.key);
        return;
      }
      if (focusedItem?.type === "provider") {
        key.preventDefault();
        setExpandedProviders((prev) => {
          const next = new Set(prev);
          if (next.has(focusedItem.key)) next.delete(focusedItem.key);
          else next.add(focusedItem.key);
          return next;
        });
        return;
      }
      if (focusedItem?.type === "radio" && focusedItem.key === "headersMode") {
        key.preventDefault();
        const modes: Array<"none" | "default" | "custom"> = [
          "none",
          "default",
          "custom",
        ];
        const idx = modes.indexOf(state.headers.mode);
        setState((prev) => ({
          ...prev,
          headers: {
            ...prev.headers,
            mode: modes[(idx + 1) % modes.length]!,
          },
        }));
        return;
      }
      // Don't prevent default for input fields - space is a valid character
      return;
    }

    // Enter - toggle sections, add list items, or start pentest
    if (key.name === "return") {
      key.preventDefault();

      // Section headers toggle expansion
      if (focusedItem?.type === "section") {
        toggleSection(focusedItem.key);
        return;
      }

      // Provider headers toggle expansion
      if (focusedItem?.type === "provider") {
        setExpandedProviders((prev) => {
          const next = new Set(prev);
          if (next.has(focusedItem.key)) next.delete(focusedItem.key);
          else next.add(focusedItem.key);
          return next;
        });
        return;
      }

      // List-adder inputs: add items on Enter
      if (focusedItem?.key === "host" && hostInput.trim()) {
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
      if (focusedItem?.key === "port" && portInput.trim()) {
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
      if (focusedItem?.key === "headerValue" && headerNameInput.trim()) {
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

      // Default: start pentest
      if (state.target.trim()) {
        createSessionAndNavigate();
      } else {
        setTargetError("Target URL is required");
      }
      return;
    }

    // Left/Right - expand/collapse sections & providers, cycle radios
    if (key.name === "left" || key.name === "right") {
      if (focusedItem?.type === "section") {
        key.preventDefault();
        if (key.name === "right") expandSection(focusedItem.key);
        else collapseSection(focusedItem.key);
        return;
      }
      if (focusedItem?.type === "provider") {
        key.preventDefault();
        if (key.name === "right") {
          setExpandedProviders((prev) => new Set([...prev, focusedItem.key]));
        } else {
          setExpandedProviders((prev) => {
            const next = new Set(prev);
            next.delete(focusedItem.key);
            return next;
          });
        }
        return;
      }
      if (focusedItem?.type === "model") {
        key.preventDefault();
        const modelInfo = availableModels.find((m) => m.id === focusedItem.key);
        if (modelInfo && key.name === "left") {
          setExpandedProviders((prev) => {
            const next = new Set(prev);
            next.delete(modelInfo.provider);
            return next;
          });
          const provIdx = navItems.findIndex(
            (i) => i.id === `provider-${modelInfo.provider}`,
          );
          if (provIdx >= 0) setFocusedIndex(provIdx);
        }
        return;
      }
      if (focusedItem?.type === "radio" && focusedItem.key === "headersMode") {
        key.preventDefault();
        const modes: Array<"none" | "default" | "custom"> = [
          "none",
          "default",
          "custom",
        ];
        const idx = modes.indexOf(state.headers.mode);
        const newIdx =
          key.name === "left"
            ? (idx - 1 + modes.length) % modes.length
            : (idx + 1) % modes.length;
        setState((prev) => ({
          ...prev,
          headers: { ...prev.headers, mode: modes[newIdx]! },
        }));
        return;
      }
      // Don't intercept left/right for input fields (cursor movement)
    }
  });

  // Mode labels
  const modeLabel = autoMode ? "Auto Mode" : "Driver Mode";
  const modeDescription = autoMode
    ? "Automated pentesting - agents run autonomously"
    : "Manual orchestration - you direct the agents";

  // Helper to check if an item is focused
  const isFocused = (id: string) => focusedItem?.id === id;

  // Render creating state
  if (isCreating) {
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

  // Render single-page scrollable form
  return (
    <Dialog size="large" onClose={onClose}>
      <box width="100%" flexDirection="column" flexShrink={1} overflow="hidden">
        {/* Header (pinned) */}
        <box
          flexDirection="column"
          flexShrink={0}
          paddingLeft={4}
          paddingBottom={1}
        >
          <text fg={colors.text}>Configure Web App Pentest</text>
          <text fg={colors.textMuted}>{modeDescription}</text>
          <text fg={colors.textMuted}>
            Model: {model.name} [{isModelUserSelected ? "user" : "default"}]
          </text>
          {error && <text fg={colors.error}>Error: {error}</text>}
        </box>

        {/* Scrollable form content */}
        <scrollbox
          ref={scrollBoxRef}
          style={{
            rootOptions: {
              flexGrow: 1,
              flexShrink: 1,
              width: "100%",
              overflow: "hidden",
            },
            contentOptions: { flexDirection: "column" },
            scrollbarOptions: { visible: true },
          }}
          stickyScroll={false}
        >
          {/* Target URL */}
          <box id="field-target" paddingLeft={4} paddingRight={2}>
            <Input
              compact
              label="Target URL"
              description="e.g., https://example.com"
              placeholder="https://example.com"
              value={state.target}
              onInput={(v) => {
                setTargetError(null);
                setState((prev) => ({ ...prev, target: v }));
              }}
              focused={isFocused("field-target")}
            />
          </box>
          {targetError && (
            <box paddingLeft={4}>
              <text fg={colors.error}>{targetError}</text>
            </box>
          )}

          {/* Source Code Access toggle */}
          <box
            id="field-sourceCodeAccess"
            paddingLeft={4}
            flexDirection="row"
            gap={1}
          >
            <text
              fg={
                isFocused("field-sourceCodeAccess")
                  ? colors.primary
                  : colors.textMuted
              }
            >
              Source Code Access:
            </text>
            <text
              fg={state.sourceCodeAccess ? colors.primary : colors.textMuted}
            >
              {state.sourceCodeAccess ? "● Enabled" : "○ Disabled"}
            </text>
            {isFocused("field-sourceCodeAccess") && (
              <text fg={colors.textMuted}>(Space to toggle)</text>
            )}
          </box>

          {/* Codebase Path (conditional on source code access) */}
          {state.sourceCodeAccess && (
            <box id="field-cwd" paddingLeft={4} paddingRight={2}>
              <Input
                compact
                label="Codebase Path"
                description="Path to the source code directory"
                placeholder={process.cwd()}
                value={state.cwd}
                onInput={(v) => setState((prev) => ({ ...prev, cwd: v }))}
                focused={isFocused("field-cwd")}
              />
            </box>
          )}

          {/* Advanced section header */}
          <box id="section-advanced" paddingLeft={4} paddingTop={1}>
            <text
              fg={
                isFocused("section-advanced")
                  ? colors.primary
                  : advancedExpanded
                    ? colors.text
                    : colors.textMuted
              }
            >
              {isFocused("section-advanced")
                ? "❯"
                : advancedExpanded
                  ? "▾"
                  : "▸"}{" "}
              Advanced
            </text>
          </box>

          {/* Advanced contents */}
          {advancedExpanded && (
            <>
              {/* Authentication section */}
              <box id="section-auth" paddingLeft={6}>
                <text
                  fg={
                    isFocused("section-auth")
                      ? colors.primary
                      : authExpanded
                        ? colors.text
                        : colors.textMuted
                  }
                >
                  {isFocused("section-auth") ? "❯" : authExpanded ? "▾" : "▸"}{" "}
                  Authentication
                </text>
              </box>

              {authExpanded && (
                <>
                  <box id="field-loginUrl" paddingLeft={8} paddingRight={2}>
                    <Input
                      compact
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
                        const cleaned = String(event.text).replace(
                          /\r?\n/g,
                          " ",
                        );
                        setState((prev) => ({
                          ...prev,
                          auth: {
                            ...prev.auth,
                            loginUrl: prev.auth.loginUrl + cleaned,
                          },
                        }));
                      }}
                      focused={isFocused("field-loginUrl")}
                    />
                  </box>
                  <box id="field-username" paddingLeft={8} paddingRight={2}>
                    <Input
                      compact
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
                        const cleaned = String(event.text).replace(
                          /\r?\n/g,
                          " ",
                        );
                        setState((prev) => ({
                          ...prev,
                          auth: {
                            ...prev.auth,
                            username: prev.auth.username + cleaned,
                          },
                        }));
                      }}
                      focused={isFocused("field-username")}
                    />
                  </box>
                  <box id="field-password" paddingLeft={8} paddingRight={2}>
                    <Input
                      compact
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
                        const cleaned = String(event.text).replace(
                          /\r?\n/g,
                          " ",
                        );
                        setState((prev) => ({
                          ...prev,
                          auth: {
                            ...prev.auth,
                            password: prev.auth.password + cleaned,
                          },
                        }));
                      }}
                      focused={isFocused("field-password")}
                    />
                  </box>
                  <box id="field-instructions" paddingLeft={8} paddingRight={2}>
                    <Input
                      compact
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
                        const cleaned = String(event.text).replace(
                          /\r?\n/g,
                          " ",
                        );
                        setState((prev) => ({
                          ...prev,
                          auth: {
                            ...prev.auth,
                            instructions: prev.auth.instructions + cleaned,
                          },
                        }));
                      }}
                      focused={isFocused("field-instructions")}
                    />
                  </box>
                </>
              )}

              {/* Scope Constraints section */}
              <box id="section-scope" paddingLeft={6}>
                <text
                  fg={
                    isFocused("section-scope")
                      ? colors.primary
                      : scopeExpanded
                        ? colors.text
                        : colors.textMuted
                  }
                >
                  {isFocused("section-scope") ? "❯" : scopeExpanded ? "▾" : "▸"}{" "}
                  Scope Constraints
                </text>
              </box>

              {scopeExpanded && (
                <>
                  <box id="field-host" paddingLeft={8} paddingRight={2}>
                    <Input
                      compact
                      label="Add Allowed Host"
                      description="Press Enter to add"
                      placeholder="example.com"
                      value={hostInput}
                      onInput={setHostInput}
                      focused={isFocused("field-host")}
                    />
                  </box>
                  {state.scope.allowedHosts.length > 0 && (
                    <box flexDirection="column" paddingLeft={10}>
                      {state.scope.allowedHosts.map((h, i) => (
                        <text key={i} fg={colors.textMuted}>
                          • {h}
                        </text>
                      ))}
                    </box>
                  )}
                  <box id="field-port" paddingLeft={8} paddingRight={2}>
                    <Input
                      compact
                      label="Add Allowed Port"
                      description="Press Enter to add"
                      placeholder="443"
                      value={portInput}
                      onInput={setPortInput}
                      focused={isFocused("field-port")}
                    />
                  </box>
                  {state.scope.allowedPorts.length > 0 && (
                    <box flexDirection="column" paddingLeft={10}>
                      {state.scope.allowedPorts.map((p, i) => (
                        <text key={i} fg={colors.textMuted}>
                          • {p}
                        </text>
                      ))}
                    </box>
                  )}
                  <box
                    id="field-strictScope"
                    paddingLeft={8}
                    flexDirection="row"
                    gap={1}
                  >
                    <text
                      fg={
                        isFocused("field-strictScope")
                          ? colors.primary
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
                      {state.scope.strictScope ? "● Enabled" : "○ Disabled"}
                    </text>
                    {isFocused("field-strictScope") && (
                      <text fg={colors.textMuted}>(Space to toggle)</text>
                    )}
                  </box>
                  <box
                    id="field-enumerateSubdomains"
                    paddingLeft={8}
                    flexDirection="row"
                    gap={1}
                  >
                    <text
                      fg={
                        isFocused("field-enumerateSubdomains")
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
                        ? "● Enabled"
                        : "○ Disabled"}
                    </text>
                    {isFocused("field-enumerateSubdomains") && (
                      <text fg={colors.textMuted}>(Space to toggle)</text>
                    )}
                  </box>
                </>
              )}

              {/* Request Headers section */}
              <box id="section-headers" paddingLeft={6}>
                <text
                  fg={
                    isFocused("section-headers")
                      ? colors.primary
                      : headersExpanded
                        ? colors.text
                        : colors.textMuted
                  }
                >
                  {isFocused("section-headers")
                    ? "❯"
                    : headersExpanded
                      ? "▾"
                      : "▸"}{" "}
                  Request Headers
                </text>
              </box>

              {headersExpanded && (
                <>
                  <box
                    id="field-headersMode"
                    paddingLeft={8}
                    flexDirection="column"
                  >
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
                    {isFocused("field-headersMode") && (
                      <text fg={colors.textMuted}>Space or ←/→ to change</text>
                    )}
                  </box>

                  {state.headers.mode === "custom" && (
                    <>
                      <box
                        id="field-headerName"
                        paddingLeft={8}
                        paddingRight={2}
                      >
                        <Input
                          compact
                          label="Header Name"
                          placeholder="X-Custom-Header"
                          value={headerNameInput}
                          onInput={setHeaderNameInput}
                          focused={isFocused("field-headerName")}
                        />
                      </box>
                      <box
                        id="field-headerValue"
                        paddingLeft={8}
                        paddingRight={2}
                      >
                        <Input
                          compact
                          label="Header Value"
                          description="Press Enter to add header"
                          placeholder="value"
                          value={headerValueInput}
                          onInput={setHeaderValueInput}
                          focused={isFocused("field-headerValue")}
                        />
                      </box>
                      {Object.keys(state.headers.customHeaders).length > 0 && (
                        <box flexDirection="column" paddingLeft={10}>
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

              {/* AI Model section */}
              <box id="section-model" paddingLeft={6}>
                <text>
                  <span
                    fg={
                      isFocused("section-model")
                        ? colors.primary
                        : modelSectionExpanded
                          ? colors.text
                          : colors.textMuted
                    }
                  >
                    {isFocused("section-model")
                      ? "❯"
                      : modelSectionExpanded
                        ? "▾"
                        : "▸"}{" "}
                    AI Model
                  </span>
                  <span fg={colors.textMuted}>
                    {" "}
                    ({model.name}) [{isModelUserSelected ? "user" : "default"}]
                  </span>
                </text>
              </box>

              {modelSectionExpanded &&
                providerOrder.map((provider) => {
                  const models = groupedModels[provider];
                  if (!models || models.length === 0) return null;
                  const isExpanded = expandedProviders.has(provider);
                  const provName = providerNames[provider] || provider;

                  return (
                    <box key={provider} flexDirection="column">
                      <box id={`provider-${provider}`} paddingLeft={8}>
                        <text
                          fg={
                            isFocused(`provider-${provider}`)
                              ? colors.primary
                              : isExpanded
                                ? colors.text
                                : colors.textMuted
                          }
                        >
                          {isFocused(`provider-${provider}`)
                            ? "❯"
                            : isExpanded
                              ? "▾"
                              : "▸"}{" "}
                          {provName} ({models.length})
                        </text>
                      </box>
                      {isExpanded &&
                        models.map((m) => {
                          const isSelected = m.id === model.id;
                          return (
                            <box
                              key={m.id}
                              id={`model-${m.id}`}
                              paddingLeft={10}
                            >
                              <text
                                fg={
                                  isFocused(`model-${m.id}`)
                                    ? colors.primary
                                    : colors.textMuted
                                }
                              >
                                {isSelected ? "●" : "○"} {m.name}
                              </text>
                            </box>
                          );
                        })}
                    </box>
                  );
                })}
            </>
          )}
        </scrollbox>

        {/* Footer help text (pinned) */}
        <box
          flexDirection="column"
          flexShrink={0}
          paddingLeft={4}
          paddingTop={1}
          paddingBottom={1}
        >
          <text>
            <span fg={colors.primary}>█ </span>
            <span fg={colors.textMuted}>Press </span>
            <span fg={colors.text}>[Enter]</span>
            <span fg={colors.textMuted}> to start pentest ({modeLabel})</span>
          </text>
          <text>
            <span fg={colors.primary}>█ </span>
            <span fg={colors.textMuted}>Press </span>
            <span fg={colors.text}>[↑/↓]</span>
            <span fg={colors.textMuted}> to navigate</span>
          </text>
          <text>
            <span fg={colors.primary}>█ </span>
            <span fg={colors.textMuted}>Press </span>
            <span fg={colors.text}>[ESC]</span>
            <span fg={colors.textMuted}> to cancel</span>
          </text>
        </box>
      </box>
    </Dialog>
  );
}
