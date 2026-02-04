/**
 * Agent Chat View
 *
 * Full-screen view for interacting with a running agent.
 * Shows message stream and allows user to inject instructions.
 */

import { useState, useCallback } from "react";
import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import type { PentestTarget } from "../../../core/agent/attackSurfaceAgent/types";
import type { DiscoveredEndpoint } from "../../../core/agent/driverModeAgent/targetExtractor";
import type { DisplayMessage } from "../agent-display";
import AgentDisplay from "../agent-display";
import MentionAutocomplete from "./mention-autocomplete";

// Color palette
const greenBullet = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);

/**
 * Agent type expected by the chat view
 */
interface ChatAgent {
  id: string;
  name: string;
  target: PentestTarget;
  status: 'running' | 'paused' | 'completed' | 'failed';
  messages: DisplayMessage[];
}

interface AgentChatViewProps {
  agent: ChatAgent;
  endpoints: DiscoveredEndpoint[];
  onSendMessage: (message: string) => void;
  onBack: () => void;
  onStop: () => void;
}

export default function AgentChatView({
  agent,
  endpoints,
  onSendMessage,
  onBack,
  onStop,
}: AgentChatViewProps) {
  const [inputValue, setInputValue] = useState('');
  const [showMentions, setShowMentions] = useState(false);
  const [mentionQuery, setMentionQuery] = useState('');

  // Status display
  const statusIcon = {
    running: '◐',
    paused: '◑',
    completed: '✓',
    failed: '✗',
  }[agent.status];

  const statusColor = {
    running: greenBullet,
    paused: RGBA.fromInts(255, 193, 7, 255),
    completed: greenBullet,
    failed: RGBA.fromInts(244, 67, 54, 255),
  }[agent.status];

  // Handle input changes
  const handleInput = useCallback((value: string) => {
    setInputValue(value);

    // Check for @ mention trigger
    const lastAtIndex = value.lastIndexOf('@');
    if (lastAtIndex !== -1 && lastAtIndex === value.length - 1) {
      // Just typed @
      setShowMentions(true);
      setMentionQuery('');
    } else if (lastAtIndex !== -1) {
      // Typing after @
      const afterAt = value.substring(lastAtIndex + 1);
      if (!afterAt.includes(' ')) {
        setShowMentions(true);
        setMentionQuery(afterAt);
      } else {
        setShowMentions(false);
      }
    } else {
      setShowMentions(false);
    }
  }, []);

  // Handle mention selection - insert the actual URL
  const handleMentionSelect = useCallback((endpoint: DiscoveredEndpoint) => {
    const lastAtIndex = inputValue.lastIndexOf('@');
    const newValue = inputValue.substring(0, lastAtIndex) + endpoint.url + ' ';
    setInputValue(newValue);
    setShowMentions(false);
  }, [inputValue]);

  // Handle message send
  const handleSend = useCallback(() => {
    if (inputValue.trim()) {
      onSendMessage(inputValue.trim());
      setInputValue('');
      setShowMentions(false);
    }
  }, [inputValue, onSendMessage]);

  // Keyboard handling
  useKeyboard((key) => {
    // Shift+/ to return to dashboard (agent continues running)
    if (key.shift && key.name === '/') {
      onBack();
      return;
    }

    // Ctrl+C to stop agent
    if (key.ctrl && key.name === 'c') {
      onStop();
      return;
    }

    // ESC to close mentions or go back
    if (key.name === 'escape') {
      if (showMentions) {
        setShowMentions(false);
      } else {
        onBack();
      }
      return;
    }

    // Enter to send message (if not in mentions)
    if (key.name === 'return' && !showMentions) {
      handleSend();
      return;
    }
  });

  return (
    <box flexDirection="column" width="100%" height="100%" flexGrow={1}>
      {/* Header */}
      <box
        flexDirection="row"
        justifyContent="space-between"
        paddingLeft={2}
        paddingRight={2}
        paddingTop={1}
        paddingBottom={1}
        border={["bottom"]}
        borderColor={dimText}
      >
        <box flexDirection="column">
          <text fg={creamText}>
            <span fg={statusColor}>{statusIcon} </span>
            {agent.name}
          </text>
          <text fg={dimText}>Target: {agent.target.target}</text>
        </box>
        <text fg={dimText}>
          {agent.status === 'running' ? 'Running...' : agent.status}
        </text>
      </box>

      {/* Message stream */}
      <box flexGrow={1} padding={1}>
        <AgentDisplay
          messages={agent.messages}
          isStreaming={agent.status === 'running'}
          focused={!showMentions}
        />
      </box>

      {/* Input area */}
      <box
        flexDirection="column"
        paddingLeft={2}
        paddingRight={2}
        paddingTop={1}
        paddingBottom={1}
        border={["top"]}
        borderColor={dimText}
        gap={1}
      >
        {/* Mention autocomplete (positioned above input) */}
        {showMentions && (
          <MentionAutocomplete
            endpoints={endpoints}
            query={mentionQuery}
            onSelect={handleMentionSelect}
            onClose={() => setShowMentions(false)}
          />
        )}

        {/* Input row */}
        <box flexDirection="row" alignItems="center" width="100%">
          <text fg={greenBullet}>{'> '}</text>
          <box flexGrow={1}>
            <input
              value={inputValue}
              onInput={handleInput}
              focused={!showMentions}
              placeholder="Type to direct agent... (@endpoint for mentions)"
            />
          </box>
        </box>

        {/* Help text */}
        <text fg={dimText}>
          [Enter] Send | [@] Mention endpoint | [Shift+/] Back to dashboard | [Ctrl+C] Stop
        </text>
      </box>
    </box>
  );
}
