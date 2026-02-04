/**
 * Mention Autocomplete
 *
 * Popup showing filtered endpoints for @mention selection.
 */

import { useState, useMemo, useEffect } from "react";
import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import type { DiscoveredEndpoint } from "../../../core/agent/driverModeAgent/targetExtractor";

// Color palette
const greenBullet = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);
const darkBg = RGBA.fromInts(20, 20, 20, 255);

interface MentionAutocompleteProps {
  endpoints: DiscoveredEndpoint[];
  query: string;
  onSelect: (endpoint: DiscoveredEndpoint) => void;
  onClose: () => void;
}

export default function MentionAutocomplete({
  endpoints,
  query,
  onSelect,
  onClose,
}: MentionAutocompleteProps) {
  const [selectedIndex, setSelectedIndex] = useState(0);

  // Filter endpoints based on query
  const filteredEndpoints = useMemo(() => {
    if (!query) return endpoints.slice(0, 5);

    const lowerQuery = query.toLowerCase();
    return endpoints
      .filter(e =>
        e.id.toLowerCase().includes(lowerQuery) ||
        e.url.toLowerCase().includes(lowerQuery) ||
        e.suggestedObjective.toLowerCase().includes(lowerQuery)
      )
      .slice(0, 5);
  }, [endpoints, query]);

  // Reset selection when filtered list changes
  useEffect(() => {
    setSelectedIndex(0);
  }, [filteredEndpoints.length]);

  // Keyboard navigation
  useKeyboard((key) => {
    if (key.name === 'up') {
      setSelectedIndex(prev => Math.max(0, prev - 1));
      return;
    }

    if (key.name === 'down') {
      setSelectedIndex(prev => Math.min(filteredEndpoints.length - 1, prev + 1));
      return;
    }

    if (key.name === 'return') {
      if (filteredEndpoints[selectedIndex]) {
        onSelect(filteredEndpoints[selectedIndex]);
      }
      return;
    }

    if (key.name === 'escape') {
      onClose();
      return;
    }

    if (key.name === 'tab') {
      if (filteredEndpoints[selectedIndex]) {
        onSelect(filteredEndpoints[selectedIndex]);
      }
      return;
    }
  });

  if (filteredEndpoints.length === 0) {
    return (
      <box
        border
        borderColor={dimText}
        backgroundColor={darkBg}
        padding={1}
      >
        <text fg={dimText}>No matching endpoints</text>
      </box>
    );
  }

  return (
    <box
      flexDirection="column"
      border
      borderColor={greenBullet}
      backgroundColor={darkBg}
      padding={1}
      gap={0}
    >
      <text fg={dimText}>Select endpoint (↑↓ to navigate, Enter to select)</text>

      {filteredEndpoints.map((endpoint, index) => (
        <MentionItem
          key={endpoint.id}
          endpoint={endpoint}
          selected={index === selectedIndex}
        />
      ))}
    </box>
  );
}

/**
 * Individual mention item
 */
function MentionItem({
  endpoint,
  selected,
}: {
  endpoint: DiscoveredEndpoint;
  selected: boolean;
}) {
  // Truncate URL for display
  const displayUrl = endpoint.url.length > 50
    ? endpoint.url.substring(0, 47) + '...'
    : endpoint.url;

  return (
    <box
      flexDirection="row"
      gap={1}
      backgroundColor={selected ? greenBullet : 'transparent'}
    >
      <text fg={selected ? darkBg : greenBullet}>@{endpoint.id}</text>
      <text fg={selected ? darkBg : creamText}>{displayUrl}</text>
    </box>
  );
}
