import { useState, useEffect } from "react";
import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import Input from "../input";
import { useRoute } from "../../context/route";
import { Session } from "../../../core/session";
import { SpinnerDots } from "../sprites";
import { generateRandomName } from "../../../util/name";
import { detectAvailableTools, hasMinimumTools, getInstallInstructions } from "../../../core/static/external/detector";
import type { ToolAvailability } from "../../../core/static/types";
import { existsSync } from "fs";
import { execSync } from "child_process";
import path from "path";

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

export default function StaticWizard({ initialRepo, initialRef, fastMode = false }: StaticWizardProps) {
  const route = useRoute();

  // Determine if initialRepo is a URL or local path
  const isUrl = initialRepo?.startsWith("http") || initialRepo?.startsWith("git@");
  const initialStep: WizardStep = initialRepo ? "checking" : "repo";

  // Wizard state
  const [currentStep, setCurrentStep] = useState<WizardStep>(initialStep);
  const [state, setState] = useState<WizardState>(() => ({
    name: generateRandomName(),
    repoPath: isUrl ? "" : (initialRepo || ""),
    repoUrl: isUrl ? (initialRepo || "") : "",
    ref: initialRef || "HEAD",
    fastMode: fastMode,
    skipTools: [],
  }));

  // UI state
  const [focusedField, setFocusedField] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [toolAvailability, setToolAvailability] = useState<ToolAvailability | null>(null);

  // Check tools on mount
  useEffect(() => {
    if (currentStep === "checking") {
      checkToolsAndRepo();
    }
  }, []);

  // Check available tools and validate repo
  async function checkToolsAndRepo() {
    setCurrentStep("checking");
    setError(null);

    try {
      // Detect available tools
      const tools = await detectAvailableTools();
      setToolAvailability(tools);

      if (!hasMinimumTools(tools)) {
        const instructions = getInstallInstructions(tools);
        setError(`Minimum tools not available. Please install Semgrep:\n${instructions[0]}`);
        setCurrentStep("repo");
        return;
      }

      // Validate repo path if local
      if (state.repoPath) {
        const resolvedPath = path.resolve(state.repoPath);
        if (!existsSync(resolvedPath)) {
          setError(`Repository path does not exist: ${resolvedPath}`);
          setCurrentStep("repo");
          return;
        }

        // Check if it's a git repo
        try {
          execSync(`git -C "${resolvedPath}" rev-parse --git-dir`, { encoding: 'utf-8', stdio: 'pipe' });
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

  // Create session and navigate
  async function createSessionAndNavigate() {
    if (!state.repoPath && !state.repoUrl) return;

    setCurrentStep("creating");
    setError(null);

    try {
      // Clone if URL provided
      let repoPath = state.repoPath;
      if (state.repoUrl && !state.repoPath) {
        // TODO: Clone to temp directory
        setError("Remote repository cloning not yet implemented. Please provide a local path.");
        setCurrentStep("configure");
        return;
      }

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

      // Navigate to static session route
      route.navigate({
        type: "static-session",
        runId: session.id,
        sessionId: session.id,
      });
    } catch (e) {
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

    // Configure step
    if (currentStep === "configure") {
      if (key.name === "return") {
        createSessionAndNavigate();
        return;
      }
      if (key.name === "tab") {
        if (key.shift) {
          setFocusedField(prev => Math.max(0, prev - 1));
        } else {
          setFocusedField(prev => Math.min(2, prev + 1));
        }
        return;
      }
      // Arrow keys for toggles
      if ((key.name === "up" || key.name === "down") && focusedField === 2) {
        setState(prev => ({ ...prev, fastMode: !prev.fastMode }));
        return;
      }
    }
  });

  // Render checking state
  if (currentStep === "checking") {
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
        <SpinnerDots label="Checking available tools..." fg="green" />
        <text fg={dimText}>Detecting Semgrep, CodeQL, Joern, TruffleHog...</text>
      </box>
    );
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
        <SpinnerDots label="Creating analysis session..." fg="green" />
        <text fg={dimText}>Repository: {state.repoPath || state.repoUrl}</text>
        <text fg={dimText}>Ref: {state.ref}</text>
        {state.fastMode && <text fg={yellowText}>Fast mode enabled (skipping heavy analysis)</text>}
      </box>
    );
  }

  // Render repo step
  if (currentStep === "repo") {
    return (
      <box width="100%" flexDirection="column" gap={2} paddingLeft={4}>
        <text fg={creamText}>Configure Static Analysis (SAST)</text>
        <text fg={dimText}>Analyze a git repository for security vulnerabilities</text>

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

  // Render configure step
  return (
    <box width="100%" flexDirection="column" gap={2} paddingLeft={4}>
      <box flexDirection="column">
        <text fg={creamText}>Configure Static Analysis</text>
        <text fg={dimText}>Repository: {state.repoPath || state.repoUrl}</text>
        <text fg={dimText}>Ref: {state.ref}</text>
      </box>

      {error && <text fg="red">Error: {error}</text>}

      {/* Analysis Options Section */}
      <box flexDirection="column" gap={1}>
        <text>
          <span fg={greenBullet}>█ </span>
          <span fg={creamText}>Analysis Options</span>
        </text>

        <box flexDirection="column" gap={1} paddingLeft={2}>
          <Input
            label="Session Name"
            placeholder="swift-falcon"
            value={state.name}
            onInput={(v) => setState(prev => ({ ...prev, name: v }))}
            focused={focusedField === 0}
          />

          <Input
            label="Git Ref"
            description="Branch, tag, or commit"
            placeholder="HEAD"
            value={state.ref}
            onInput={(v) => setState(prev => ({ ...prev, ref: v }))}
            focused={focusedField === 1}
          />

          <box flexDirection="row" gap={1}>
            <text fg={focusedField === 2 ? creamText : dimText}>Fast Mode:</text>
            <text fg={state.fastMode ? yellowText : dimText}>
              {state.fastMode ? "● Enabled" : "○ Disabled"}
            </text>
            {focusedField === 2 && <text fg={dimText}>(↑/↓ to toggle)</text>}
          </box>
          <text fg={dimText} paddingLeft={2}>
            Fast mode skips CodeQL and Joern analysis
          </text>
        </box>
      </box>

      {/* Tool availability summary */}
      {toolAvailability && (
        <box flexDirection="column" gap={1}>
          <text>
            <span fg={greenBullet}>█ </span>
            <span fg={creamText}>Available Tools</span>
          </text>
          <box flexDirection="column" paddingLeft={2}>
            <text fg={toolAvailability.semgrep.available ? greenBullet : dimText}>
              {toolAvailability.semgrep.available ? "✓" : "○"} Semgrep
            </text>
            <text fg={toolAvailability.codeql.available ? greenBullet : dimText}>
              {toolAvailability.codeql.available ? "✓" : "○"} CodeQL
              {state.fastMode && toolAvailability.codeql.available && " (skipped in fast mode)"}
            </text>
            <text fg={toolAvailability.joern.available ? greenBullet : dimText}>
              {toolAvailability.joern.available ? "✓" : "○"} Joern
              {state.fastMode && toolAvailability.joern.available && " (skipped in fast mode)"}
            </text>
            <text fg={toolAvailability.trufflehog.available ? greenBullet : dimText}>
              {toolAvailability.trufflehog.available ? "✓" : "○"} TruffleHog (secrets)
            </text>
          </box>
        </box>
      )}

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
