import { useState, useEffect, useMemo } from "react";
import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import Input from "../input";
import { useRoute } from "../../context/route";
import { useConfig } from "../../context/config";
import { useAgent } from "../../agentProvider";
import { Session } from "../../../core/session";
import { SpinnerDots } from "../sprites";
import { generateRandomName } from "../../../util/name";
import { detectAvailableTools, hasMinimumTools, getInstallInstructions, detectSemgrep, detectCodeQL, detectJoern, detectTrufflehog, detectGrype } from "../../../core/static/external/detector";
import type { ToolAvailability } from "../../../core/static/types";
import { type ModelInfo } from "../../../core/ai";
import { getAvailableModels } from "../../../core/providers/utils";
import { existsSync } from "fs";
import { exec } from "child_process";
import { promisify } from "util";
import path from "path";
import os from "os";

const execAsync = promisify(exec);

/**
 * Expand tilde (~) to home directory in paths
 */
function expandTilde(filePath: string): string {
  if (filePath.startsWith('~/')) {
    return path.join(os.homedir(), filePath.slice(2));
  }
  if (filePath === '~') {
    return os.homedir();
  }
  return filePath;
}

// Wizard step types
type WizardStep = "repo" | "configure" | "checking" | "creating";

// Wizard state interface
interface WizardState {
  name: string;
  repoPath: string;
  repoUrl: string;
  ref: string;
  fastMode: boolean;
  skipTools: string[];
}

// Props for the StaticWizard
interface StaticWizardProps {
  /** Pre-filled repository from --repo flag */
  initialRepo?: string;
  /** Pre-filled ref from --ref flag */
  initialRef?: string;
  /** Enable fast mode from --fast flag */
  fastMode?: boolean;
}

// Color palette
const greenBullet = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);
const yellowText = RGBA.fromInts(255, 193, 7, 255);
const redText = RGBA.fromInts(244, 67, 54, 255);

export default function StaticWizard({ initialRepo, initialRef, fastMode = false }: StaticWizardProps) {
  const route = useRoute();
  const config = useConfig();
  const { model, setModel, isModelUserSelected } = useAgent();

  // Model picker state
  const [availableModels, setAvailableModels] = useState<ModelInfo[]>([]);
  const [modelSearchQuery, setModelSearchQuery] = useState("");
  const [expandedProviders, setExpandedProviders] = useState<Set<string>>(new Set(["anthropic"]));

  // Provider display names and order
  const providerNames: Record<string, string> = {
    anthropic: "Claude",
    openai: "OpenAI",
    openrouter: "OpenRouter",
    bedrock: "Bedrock",
  };
  const providerOrder = ["anthropic", "openai", "openrouter", "bedrock"];

  // Group models by provider and filter by search
  const groupedModels = useMemo(() => {
    const groups: Record<string, ModelInfo[]> = {};
    const query = modelSearchQuery.toLowerCase().trim();

    for (const m of availableModels) {
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
      // Auto-expand provider of current model
      if (models.length > 0) {
        const currentModel = models.find(m => m.id === model.id) || models[0];
        if (currentModel) {
          setExpandedProviders(new Set([currentModel.provider]));
        }
      }
    }
  }, [config.data, model.id]);

  // Determine if initialRepo is a URL or local path
  const isUrl = initialRepo?.startsWith("http") || initialRepo?.startsWith("git@");
  const initialStep: WizardStep = initialRepo ? "checking" : "repo";

  // Expand tilde in initial repo if it's a local path
  const expandedInitialRepo = initialRepo && !isUrl ? expandTilde(initialRepo) : initialRepo;

  // Wizard state
  const [currentStep, setCurrentStep] = useState<WizardStep>(initialStep);
  const [state, setState] = useState<WizardState>(() => ({
    name: generateRandomName(),
    repoPath: isUrl ? "" : (expandedInitialRepo || ""),
    repoUrl: isUrl ? (initialRepo || "") : "",
    ref: initialRef || "HEAD",
    fastMode: fastMode,
    skipTools: [],
  }));

  // UI state
  const [focusedField, setFocusedField] = useState(0);
  const [focusedSection, setFocusedSection] = useState(0); // 0=analysis, 1=tools, 2=model
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set(["analysis", "tools"]));
  const [error, setError] = useState<string | null>(null);
  const [toolAvailability, setToolAvailability] = useState<ToolAvailability | null>(null);

  // Tool checking progress state (for step-by-step telemetry)
  type ToolCheckStatus = 'pending' | 'checking' | 'found' | 'not_found';
  const [toolCheckProgress, setToolCheckProgress] = useState<{
    semgrep: ToolCheckStatus;
    codeql: ToolCheckStatus;
    joern: ToolCheckStatus;
    trufflehog: ToolCheckStatus;
    grype: ToolCheckStatus;
  }>({
    semgrep: 'pending',
    codeql: 'pending',
    joern: 'pending',
    trufflehog: 'pending',
    grype: 'pending',
  });

  // Creation progress state (for step-by-step telemetry)
  type CreationStatus = 'pending' | 'in_progress' | 'done' | 'error';
  const [creationProgress, setCreationProgress] = useState<{
    validatingPath: CreationStatus;
    checkingGit: CreationStatus;
    resolvingRef: CreationStatus;
    creatingSession: CreationStatus;
    gitBranch?: string;
    gitCommit?: string;
  }>({
    validatingPath: 'pending',
    checkingGit: 'pending',
    resolvingRef: 'pending',
    creatingSession: 'pending',
  });

  // Check tools on mount
  useEffect(() => {
    if (currentStep === "checking") {
      checkToolsAndRepo();
    }
  }, []);

  // Check available tools and validate repo with step-by-step progress (parallelized)
  async function checkToolsAndRepo() {
    setCurrentStep("checking");
    setError(null);

    // Set all to checking immediately for parallel detection
    setToolCheckProgress({
      semgrep: 'checking',
      codeql: 'checking',
      joern: 'checking',
      trufflehog: 'checking',
      grype: 'checking',
    });

    try {
      // Start all tool checks in parallel
      const semgrepPromise = detectSemgrep().then(result => {
        setToolCheckProgress(prev => ({
          ...prev,
          semgrep: result.available ? 'found' : 'not_found'
        }));
        return result;
      });

      const codeqlPromise = detectCodeQL().then(result => {
        setToolCheckProgress(prev => ({
          ...prev,
          codeql: result.available ? 'found' : 'not_found'
        }));
        return result;
      });

      const joernPromise = detectJoern().then(result => {
        setToolCheckProgress(prev => ({
          ...prev,
          joern: result.available ? 'found' : 'not_found'
        }));
        return result;
      });

      const trufflehogPromise = detectTrufflehog().then(result => {
        setToolCheckProgress(prev => ({
          ...prev,
          trufflehog: result.available ? 'found' : 'not_found'
        }));
        return result;
      });

      const grypePromise = detectGrype().then(result => {
        setToolCheckProgress(prev => ({
          ...prev,
          grype: result.available ? 'found' : 'not_found'
        }));
        return result;
      });

      // Wait for all to complete
      const [semgrep, codeql, joern, trufflehog, grype] = await Promise.all([
        semgrepPromise,
        codeqlPromise,
        joernPromise,
        trufflehogPromise,
        grypePromise,
      ]);

      const tools: ToolAvailability = { semgrep, codeql, joern, trufflehog, grype };
      setToolAvailability(tools);

      if (!hasMinimumTools(tools)) {
        const instructions = getInstallInstructions(tools);
        setError(`Minimum tools not available. Please install Semgrep:\n${instructions[0]}`);
        setCurrentStep("repo");
        return;
      }

      // Validate repo path if local (async)
      if (state.repoPath) {
        const resolvedPath = path.resolve(expandTilde(state.repoPath));
        if (!existsSync(resolvedPath)) {
          setError(`Repository path does not exist: ${resolvedPath}`);
          setCurrentStep("repo");
          return;
        }

        // Check if it's a git repo (async)
        try {
          await execAsync(`git -C "${resolvedPath}" rev-parse --git-dir`);
        } catch {
          setError(`Not a git repository: ${resolvedPath}`);
          setCurrentStep("repo");
          return;
        }

        setState(prev => ({ ...prev, repoPath: resolvedPath }));
      }

      // If we have initial repo, go to configure
      if (initialRepo) {
        setCurrentStep("configure");
      } else {
        setCurrentStep("repo");
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to check tools");
      setCurrentStep("repo");
    }
  }

  // Create session and navigate with step-by-step progress
  async function createSessionAndNavigate() {
    if (!state.repoPath && !state.repoUrl) return;

    setCurrentStep("creating");
    setError(null);

    // Reset progress
    setCreationProgress({
      validatingPath: 'in_progress',
      checkingGit: 'pending',
      resolvingRef: 'pending',
      creatingSession: 'pending',
    });

    try {
      // Clone if URL provided
      let repoPath = state.repoPath ? path.resolve(expandTilde(state.repoPath)) : "";
      if (state.repoUrl && !state.repoPath) {
        setCreationProgress(prev => ({ ...prev, validatingPath: 'error' }));
        setError("Remote repository cloning not yet implemented. Please provide a local path.");
        setCurrentStep("configure");
        return;
      }

      // Validate path exists
      if (repoPath && !existsSync(repoPath)) {
        setCreationProgress(prev => ({ ...prev, validatingPath: 'error' }));
        setError(`Repository path does not exist: ${repoPath}`);
        setCurrentStep("repo");
        return;
      }

      setCreationProgress(prev => ({
        ...prev,
        validatingPath: 'done',
        checkingGit: 'in_progress'
      }));

      // Validate it's a git repo and extract branch/commit info (async)
      if (repoPath) {
        try {
          await execAsync(`git -C "${repoPath}" rev-parse --git-dir`);

          // Get branch name (async)
          let branch = 'HEAD';
          try {
            const { stdout } = await execAsync(`git -C "${repoPath}" rev-parse --abbrev-ref HEAD`);
            branch = stdout.trim();
          } catch {
            // Fallback to HEAD
          }

          // Get commit hash (async)
          let commit = '';
          try {
            const { stdout } = await execAsync(`git -C "${repoPath}" rev-parse --short HEAD`);
            commit = stdout.trim();
          } catch {
            // Fallback to empty
          }

          setCreationProgress(prev => ({
            ...prev,
            checkingGit: 'done',
            resolvingRef: 'in_progress',
            gitBranch: branch,
            gitCommit: commit,
          }));
        } catch {
          setCreationProgress(prev => ({ ...prev, checkingGit: 'error' }));
          setError(`Not a git repository: ${repoPath}`);
          setCurrentStep("repo");
          return;
        }
      }

      // Resolving ref
      setCreationProgress(prev => ({
        ...prev,
        resolvingRef: 'done',
        creatingSession: 'in_progress'
      }));

      // Build session config
      const session = await Session.create({
        targets: [state.repoUrl || repoPath],
        name: state.name,
        config: {
          sessionType: 'static',
          staticConfig: {
            repoPath,
            repoUrl: state.repoUrl || undefined,
            ref: state.ref,
            fastMode: state.fastMode,
            skipTools: state.skipTools.length > 0 ? state.skipTools : undefined,
          },
        },
      });

      setCreationProgress(prev => ({ ...prev, creatingSession: 'done' }));

      // Navigate to static session route
      route.navigate({
        type: "static-session",
        runId: session.id,
        sessionId: session.id,
      });
    } catch (e) {
      setCreationProgress(prev => ({ ...prev, creatingSession: 'error' }));
      setError(e instanceof Error ? e.message : "Failed to create session");
      setCurrentStep("configure");
    }
  }

  // Keyboard handling
  useKeyboard((key) => {
    // ESC - Go back or close
    if (key.name === "escape") {
      if (currentStep === "creating" || currentStep === "checking") {
        return;
      }
      if (currentStep === "configure") {
        if (initialRepo) {
          route.navigate({ type: "base", path: "home" });
        } else {
          setCurrentStep("repo");
          setFocusedField(0);
        }
        return;
      }
      route.navigate({ type: "base", path: "home" });
      return;
    }

    // Don't allow navigation while checking or creating
    if (currentStep === "checking" || currentStep === "creating") return;

    // Repo step
    if (currentStep === "repo") {
      if (key.name === "tab") {
        if (key.shift) {
          setFocusedField(prev => Math.max(0, prev - 1));
        } else {
          if (focusedField >= 2 && (state.repoPath || state.repoUrl)) {
            checkToolsAndRepo().then(() => {
              if (!error) setCurrentStep("configure");
            });
          } else {
            setFocusedField(prev => Math.min(2, prev + 1));
          }
        }
        return;
      }
      if (key.name === "return" && (state.repoPath || state.repoUrl)) {
        createSessionAndNavigate();
        return;
      }
      return;
    }

    // Configure step with collapsible sections
    if (currentStep === "configure") {
      // Enter to create session (unless in model section)
      if (key.name === "return" && focusedSection !== 2) {
        createSessionAndNavigate();
        return;
      }

      // Tab navigation between sections
      if (key.name === "tab") {
        if (key.shift) {
          if (focusedField > 0) {
            setFocusedField(focusedField - 1);
          } else if (focusedSection > 0) {
            setFocusedSection(focusedSection - 1);
            // Set to last field of previous section
            const maxFields = getMaxFieldsForSection(focusedSection - 1);
            setFocusedField(maxFields - 1);
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

      // Space to toggle section expand/collapse
      if (key.name === "space" || key.sequence === " ") {
        const sectionNames = ["analysis", "tools", "model"];
        const sectionName = sectionNames[focusedSection];
        if (sectionName) {
          setExpandedSections(prev => {
            const next = new Set(prev);
            if (next.has(sectionName)) {
              next.delete(sectionName);
            } else {
              next.add(sectionName);
            }
            return next;
          });
        }
        return;
      }

      // Arrow keys for toggles in analysis section
      if ((key.name === "up" || key.name === "down") && focusedSection === 0 && focusedField === 2) {
        setState(prev => ({ ...prev, fastMode: !prev.fastMode }));
        return;
      }

      // Model section-specific handling
      if (focusedSection === 2 && expandedSections.has("model")) {
        // Arrow keys to navigate models
        if (key.name === "up" || key.name === "down") {
          const currentIdx = visibleModels.findIndex(m => m.id === model.id);
          const newIdx = key.name === "up"
            ? Math.max(0, currentIdx - 1)
            : Math.min(visibleModels.length - 1, currentIdx + 1);
          const newModel = visibleModels[newIdx];
          if (newModel) {
            setModel(newModel);
          }
          return;
        }

        // Left/Right to toggle provider expansion
        if (key.name === "left" || key.name === "right") {
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

        // Backspace to remove search char
        if (key.name === "backspace") {
          setModelSearchQuery(prev => prev.slice(0, -1));
          return;
        }

        // Typing for search
        if (key.sequence && key.sequence.length === 1 && /[a-zA-Z0-9\-_.]/.test(key.sequence)) {
          setModelSearchQuery(prev => prev + key.sequence);
          // Expand all providers when searching
          if (!modelSearchQuery) {
            setExpandedProviders(new Set(providerOrder));
          }
          return;
        }

        // Enter to confirm model selection and start
        if (key.name === "return") {
          createSessionAndNavigate();
          return;
        }
      }
    }
  });

  // Helper to get max fields for a section
  function getMaxFieldsForSection(section: number): number {
    switch (section) {
      case 0: return 3; // Analysis: name, ref, fastMode
      case 1: return 1; // Tools: just the section itself (tools are not individually focusable)
      case 2: return 1; // Model: just the section itself
      default: return 1;
    }
  }

  // Helper to get status icon and color
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'pending': return '○';
      case 'checking': case 'in_progress': return '◐';
      case 'found': case 'done': return '✓';
      case 'not_found': case 'error': return '✗';
      default: return '○';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'pending': return dimText;
      case 'checking': case 'in_progress': return yellowText;
      case 'found': case 'done': return greenBullet;
      case 'not_found': case 'error': return redText;
      default: return dimText;
    }
  };

  // Render checking state with step-by-step progress
  if (currentStep === "checking") {
    const toolNames: Record<string, string> = {
      semgrep: 'Semgrep',
      codeql: 'CodeQL',
      joern: 'Joern',
      trufflehog: 'TruffleHog',
      grype: 'Grype',
    };

    return (
      <box
        flexDirection="column"
        width="100%"
        height="100%"
        alignItems="center"
        justifyContent="center"
        flexGrow={1}
        gap={1}
      >
        <SpinnerDots label="Checking available tools..." fg="green" />
        <box flexDirection="column" gap={0} marginTop={1}>
          {(['semgrep', 'codeql', 'joern', 'trufflehog', 'grype'] as const).map(tool => {
            const status = toolCheckProgress[tool];
            const isChecking = status === 'checking';
            return (
              <box key={tool} flexDirection="row" gap={1}>
                <text fg={getStatusColor(status)}>
                  {getStatusIcon(status)}
                </text>
                <text fg={isChecking ? creamText : dimText}>
                  Detecting {toolNames[tool]}...
                </text>
                {status === 'found' && toolAvailability?.[tool]?.version && (
                  <text fg={dimText}>({toolAvailability[tool].version})</text>
                )}
              </box>
            );
          })}
        </box>
      </box>
    );
  }

  // Render creating state with step-by-step progress
  if (currentStep === "creating") {
    return (
      <box
        flexDirection="column"
        width="100%"
        height="100%"
        alignItems="center"
        justifyContent="center"
        flexGrow={1}
        gap={1}
      >
        <SpinnerDots label="Creating analysis session..." fg="green" />

        <box flexDirection="column" gap={0} marginTop={1}>
          <box flexDirection="row" gap={1}>
            <text fg={getStatusColor(creationProgress.validatingPath)}>
              {getStatusIcon(creationProgress.validatingPath)}
            </text>
            <text fg={creationProgress.validatingPath === 'in_progress' ? creamText : dimText}>
              Validating repository path...
            </text>
          </box>

          <box flexDirection="row" gap={1}>
            <text fg={getStatusColor(creationProgress.checkingGit)}>
              {getStatusIcon(creationProgress.checkingGit)}
            </text>
            <text fg={creationProgress.checkingGit === 'in_progress' ? creamText : dimText}>
              Checking git status...
            </text>
            {creationProgress.gitBranch && (
              <text fg={dimText}>({creationProgress.gitBranch})</text>
            )}
          </box>

          <box flexDirection="row" gap={1}>
            <text fg={getStatusColor(creationProgress.resolvingRef)}>
              {getStatusIcon(creationProgress.resolvingRef)}
            </text>
            <text fg={creationProgress.resolvingRef === 'in_progress' ? creamText : dimText}>
              Resolving ref: {state.ref}
            </text>
            {creationProgress.gitCommit && (
              <text fg={dimText}>({creationProgress.gitCommit})</text>
            )}
          </box>

          <box flexDirection="row" gap={1}>
            <text fg={getStatusColor(creationProgress.creatingSession)}>
              {getStatusIcon(creationProgress.creatingSession)}
            </text>
            <text fg={creationProgress.creatingSession === 'in_progress' ? creamText : dimText}>
              Creating session...
            </text>
          </box>
        </box>

        {state.fastMode && (
          <text fg={yellowText} marginTop={1}>Fast mode enabled (skipping heavy analysis)</text>
        )}
      </box>
    );
  }

  // Render repo step
  if (currentStep === "repo") {
    return (
      <box width="100%" flexDirection="column" gap={2} paddingLeft={4}>
        <text fg={creamText}>Configure Static Analysis (SAST)</text>
        <text fg={dimText}>Analyze a git repository for security vulnerabilities</text>
        <text fg={dimText}>
          Model: {model.name} [{isModelUserSelected ? "user" : "default"}]
        </text>

        {error && <text fg="red">Error: {error}</text>}

        <Input
          label="Session Name"
          description="Auto-generated, edit if desired"
          placeholder="swift-falcon"
          value={state.name}
          onInput={(v) => setState(prev => ({ ...prev, name: v }))}
          focused={focusedField === 0}
        />

        <Input
          label="Repository Path"
          description="Local path to git repository"
          placeholder="/path/to/repo"
          value={state.repoPath}
          onInput={(v) => setState(prev => ({ ...prev, repoPath: v }))}
          focused={focusedField === 1}
        />

        <Input
          label="Git Ref"
          description="Branch, tag, or commit to analyze"
          placeholder="HEAD"
          value={state.ref}
          onInput={(v) => setState(prev => ({ ...prev, ref: v }))}
          focused={focusedField === 2}
        />

        {/* Tool availability summary */}
        {toolAvailability && (
          <box flexDirection="column" gap={0} marginTop={1}>
            <text fg={dimText}>Available Tools:</text>
            <text fg={toolAvailability.semgrep.available ? greenBullet : dimText}>
              {toolAvailability.semgrep.available ? "✓" : "○"} Semgrep {toolAvailability.semgrep.version || "(not found)"}
            </text>
            <text fg={toolAvailability.codeql.available ? greenBullet : dimText}>
              {toolAvailability.codeql.available ? "✓" : "○"} CodeQL {toolAvailability.codeql.version || "(not found)"}
            </text>
            <text fg={toolAvailability.joern.available ? greenBullet : dimText}>
              {toolAvailability.joern.available ? "✓" : "○"} Joern {toolAvailability.joern.version || "(not found)"}
            </text>
            <text fg={toolAvailability.trufflehog.available ? greenBullet : dimText}>
              {toolAvailability.trufflehog.available ? "✓" : "○"} TruffleHog {toolAvailability.trufflehog.version || "(not found)"}
            </text>
          </box>
        )}

        <box flexDirection="column" gap={0} marginTop={1}>
          <text>
            <span fg={greenBullet}>█ </span>
            <span fg={dimText}>Press </span>
            <span fg={creamText}>[Enter]</span>
            <span fg={dimText}> to start analysis</span>
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

  // Render configure step with collapsible sections
  return (
    <box width="100%" flexDirection="column" gap={2} paddingLeft={4}>
      {/* Header */}
      <box flexDirection="column">
        <text fg={creamText}>Configure Static Analysis</text>
        <text fg={dimText}>Repository: {state.repoPath || state.repoUrl}</text>
        <text fg={dimText}>
          Model: {model.name} [{isModelUserSelected ? "user" : "default"}]
        </text>
      </box>

      {error && <text fg="red">Error: {error}</text>}

      {/* Analysis Options Section (Collapsible) */}
      <box flexDirection="column" gap={1}>
        <text>
          <span fg={greenBullet}>{expandedSections.has("analysis") ? "▾" : "▸"} </span>
          <span fg={focusedSection === 0 ? creamText : dimText}>Analysis Options</span>
          {focusedSection === 0 && <span fg={dimText}> [Space] to {expandedSections.has("analysis") ? "collapse" : "expand"}</span>}
        </text>
        {expandedSections.has("analysis") && (
          <box flexDirection="column" gap={1} paddingLeft={2}>
            <Input
              label="Session Name"
              placeholder="swift-falcon"
              value={state.name}
              onInput={(v) => setState(prev => ({ ...prev, name: v }))}
              focused={focusedSection === 0 && focusedField === 0}
            />

            <Input
              label="Git Ref"
              description="Branch, tag, or commit"
              placeholder="HEAD"
              value={state.ref}
              onInput={(v) => setState(prev => ({ ...prev, ref: v }))}
              focused={focusedSection === 0 && focusedField === 1}
            />

            <box flexDirection="row" gap={1}>
              <text fg={focusedSection === 0 && focusedField === 2 ? creamText : dimText}>Fast Mode:</text>
              <text fg={state.fastMode ? yellowText : dimText}>
                {state.fastMode ? "● Enabled" : "○ Disabled"}
              </text>
              {focusedSection === 0 && focusedField === 2 && <text fg={dimText}>(↑/↓ to toggle)</text>}
            </box>
            <text fg={dimText} paddingLeft={2}>
              Fast mode skips CodeQL and Joern analysis
            </text>
          </box>
        )}
      </box>

      {/* Tool Configuration Section (Collapsible) */}
      <box flexDirection="column" gap={1}>
        <text>
          <span fg={greenBullet}>{expandedSections.has("tools") ? "▾" : "▸"} </span>
          <span fg={focusedSection === 1 ? creamText : dimText}>Tool Configuration</span>
          {focusedSection === 1 && <span fg={dimText}> [Space] to {expandedSections.has("tools") ? "collapse" : "expand"}</span>}
        </text>
        {expandedSections.has("tools") && toolAvailability && (
          <box flexDirection="column" paddingLeft={2} gap={0}>
            {/* Semgrep */}
            <box flexDirection="column" gap={0}>
              <text fg={toolAvailability.semgrep.available ? greenBullet : dimText}>
                {toolAvailability.semgrep.available ? "✓" : "✗"} Semgrep
                {toolAvailability.semgrep.version && ` (${toolAvailability.semgrep.version})`}
                {!toolAvailability.semgrep.available && " - not installed"}
              </text>
              <text fg={dimText} paddingLeft={2}>Pattern-based analysis</text>
            </box>

            {/* CodeQL */}
            <box flexDirection="column" gap={0}>
              <text fg={toolAvailability.codeql.available && !state.fastMode ? greenBullet : dimText}>
                {toolAvailability.codeql.available ? (state.fastMode ? "◌" : "✓") : "✗"} CodeQL
                {toolAvailability.codeql.version && ` (${toolAvailability.codeql.version})`}
                {!toolAvailability.codeql.available && " - not installed"}
                {state.fastMode && toolAvailability.codeql.available && " - skipped in fast mode"}
              </text>
              <text fg={dimText} paddingLeft={2}>Deep semantic analysis</text>
            </box>

            {/* Joern */}
            <box flexDirection="column" gap={0}>
              <text fg={toolAvailability.joern.available && !state.fastMode ? greenBullet : dimText}>
                {toolAvailability.joern.available ? (state.fastMode ? "◌" : "✓") : "✗"} Joern
                {toolAvailability.joern.version && ` (${toolAvailability.joern.version})`}
                {!toolAvailability.joern.available && " - not installed"}
                {state.fastMode && toolAvailability.joern.available && " - skipped in fast mode"}
              </text>
              <text fg={dimText} paddingLeft={2}>Code Property Graph analysis</text>
            </box>

            {/* TruffleHog */}
            <box flexDirection="column" gap={0}>
              <text fg={toolAvailability.trufflehog.available ? greenBullet : dimText}>
                {toolAvailability.trufflehog.available ? "✓" : "✗"} TruffleHog
                {toolAvailability.trufflehog.version && ` (${toolAvailability.trufflehog.version})`}
                {!toolAvailability.trufflehog.available && " - not installed"}
              </text>
              <text fg={dimText} paddingLeft={2}>Secret detection</text>
            </box>

            {/* Grype */}
            <box flexDirection="column" gap={0}>
              <text fg={toolAvailability.grype.available ? greenBullet : dimText}>
                {toolAvailability.grype.available ? "✓" : "✗"} Grype
                {toolAvailability.grype.version && ` (${toolAvailability.grype.version})`}
                {!toolAvailability.grype.available && " - not installed"}
              </text>
              <text fg={dimText} paddingLeft={2}>Dependency scanning</text>
            </box>
          </box>
        )}
      </box>

      {/* AI Model Section (Collapsible with picker) */}
      <box flexDirection="column" gap={1}>
        <text>
          <span fg={greenBullet}>{expandedSections.has("model") ? "▾" : "▸"} </span>
          <span fg={focusedSection === 2 ? creamText : dimText}>AI Model</span>
          <span fg={dimText}> ({model.name})</span>
          <span fg={dimText}> [{isModelUserSelected ? "user" : "default"}]</span>
          {focusedSection === 2 && <span fg={dimText}> [Space] to {expandedSections.has("model") ? "collapse" : "expand"}</span>}
        </text>
        {expandedSections.has("model") && (
          <box flexDirection="column" gap={0} paddingLeft={2}>
            {/* Search input */}
            {modelSearchQuery ? (
              <text fg={creamText}>Search: {modelSearchQuery}_</text>
            ) : (
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
                  <text fg={isExpanded ? creamText : dimText}>
                    {isExpanded ? "▾" : "▸"} {providerName} ({models.length})
                  </text>

                  {/* Models list (when expanded) */}
                  {isExpanded && (
                    <box flexDirection="column" gap={0} paddingLeft={2}>
                      {models.map((m) => {
                        const isSelected = m.id === model.id;
                        return (
                          <text key={m.id} fg={isSelected ? greenBullet : dimText}>
                            {isSelected ? "●" : "○"} {m.name}
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

      {/* Footer hints */}
      <box flexDirection="column" gap={0} marginTop={1}>
        <text>
          <span fg={greenBullet}>█ </span>
          <span fg={dimText}>Press </span>
          <span fg={creamText}>[Enter]</span>
          <span fg={dimText}> to start static analysis</span>
        </text>
        <text>
          <span fg={greenBullet}>█ </span>
          <span fg={dimText}>Press </span>
          <span fg={creamText}>[Tab]</span>
          <span fg={dimText}> to navigate sections</span>
        </text>
        <text>
          <span fg={greenBullet}>█ </span>
          <span fg={dimText}>Press </span>
          <span fg={creamText}>[Space]</span>
          <span fg={dimText}> to expand/collapse</span>
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
