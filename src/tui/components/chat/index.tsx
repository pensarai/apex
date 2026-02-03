/**
 * Chat TUI - Main Entry Point
 *
 * A Claude Code-inspired chat interface for Apex with:
 * - Home view with petri animation and session management
 * - Config view for target configuration
 * - Chat view with message display, tool trees, and approval prompts
 * - Collapsible sidebar with attack surface, credentials, and vulnerabilities
 */

import { useState, useCallback, useEffect } from "react";
import { Session } from "../../../core/session";
import { useConfig } from "../../context/config";
import { useAgent } from "../../context/agent";
import { HomeView } from "./home-view";
import { ConfigView, type SessionConfig } from "./config-view";
import { Session as SessionComponent } from "../../session";
import type { ModelInfo } from "../../../core/ai";

type ChatAppView = "home" | "config" | "chat";

interface ChatAppProps {
  /** Initial view to show */
  initialView?: ChatAppView;
  /** Initial session ID (for resume) */
  initialSessionId?: string;
  /** Is this a resume? */
  isResume?: boolean;
}

export function ChatApp({
  initialView = "home",
  initialSessionId,
  isResume: initialIsResume = false,
}: ChatAppProps) {
  const config = useConfig();
  const { model } = useAgent();

  // View state
  const [currentView, setCurrentView] = useState<ChatAppView>(initialView);
  const [activeSession, setActiveSession] = useState<Session.SessionInfo | null>(null);
  const [isResume, setIsResume] = useState(initialIsResume);
  const [sessionModel, setSessionModel] = useState<ModelInfo>(model);
  const [initialDirective, setInitialDirective] = useState<string | undefined>(undefined);

  // Load initial session if provided
  useEffect(() => {
    if (initialSessionId) {
      Session.get(initialSessionId).then((session) => {
        if (session) {
          setActiveSession(session);
          setCurrentView("chat");
          setIsResume(initialIsResume);
        }
      });
    }
  }, [initialSessionId]);

  // Handle view navigation
  const handleNavigate = useCallback((
    view: ChatAppView,
    options?: { sessionId?: string; isResume?: boolean }
  ) => {
    if (view === "chat" && options?.sessionId) {
      // Resume session
      Session.get(options.sessionId).then((session) => {
        if (session) {
          setActiveSession(session);
          setIsResume(options.isResume ?? false);
          setCurrentView("chat");
        }
      });
    } else {
      setCurrentView(view);
    }
  }, []);

  // Handle starting a new session from home (exploration mode)
  const handleStartSession = useCallback(async (directive: string) => {
    // Create exploration session (no target)
    const session = await Session.create({
      name: `exploration-${Date.now()}`,
      targets: [],
    });
    setActiveSession(session);
    setInitialDirective(directive); // Pass directive to Session component
    setIsResume(false);
    setCurrentView("chat");
  }, []);

  // Handle config form submission
  const handleConfigSubmit = useCallback(async (configData: SessionConfig) => {
    // Generate session name from URL hostname
    const hostname = parseHostFromTarget(configData.targetUrl);
    const timestamp = new Date().toISOString().split("T")[0];
    const sessionName = `${hostname}-${timestamp}`;

    // Create session
    const session = await Session.create({
      name: sessionName,
      targets: [configData.targetUrl],
      config: {
        scopeConstraints: {
          strictScope: configData.strictScope,
          allowedHosts: configData.strictScope ? [hostname] : undefined,
        },
        operatorSettings: {
          initialMode: "manual",
          autoApproveTier: 2,
          enableSuggestions: true,
        },
      },
    });

    setActiveSession(session);
    setSessionModel(configData.model);
    setIsResume(false);
    setCurrentView("chat");
  }, []);

  // Handle exit from chat view
  const handleExitChat = useCallback(() => {
    setCurrentView("home");
    setActiveSession(null);
    setIsResume(false);
    setInitialDirective(undefined);
  }, []);

  // Handle back from config
  const handleBackFromConfig = useCallback(() => {
    setCurrentView("home");
  }, []);

  return (
    <box flexDirection="column" width="100%" height="100%" flexGrow={1}>
      {currentView === "home" && (
        <HomeView
          onNavigate={handleNavigate}
          onStartSession={handleStartSession}
        />
      )}

      {currentView === "config" && (
        <ConfigView
          config={config.data}
          onBack={handleBackFromConfig}
          onStart={handleConfigSubmit}
        />
      )}

      {currentView === "chat" && activeSession && (
        <SessionComponent
          session={activeSession}
          mode="chat"
          model={sessionModel}
          isResume={isResume}
          initialDirective={initialDirective}
          onExit={handleExitChat}
        />
      )}
    </box>
  );
}

/**
 * Parse hostname from target URL
 */
function parseHostFromTarget(target: string): string {
  try {
    const url = new URL(target);
    return url.hostname;
  } catch {
    return target.replace(/:(\d+)$/, "");
  }
}

export default ChatApp;
