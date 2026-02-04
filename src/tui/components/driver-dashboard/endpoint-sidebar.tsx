/**
 * Endpoint Sidebar
 *
 * Shows discovered endpoints from recon with ability to spawn agents.
 */

import { RGBA } from "@opentui/core";
import type { DiscoveredEndpoint } from "../../../core/agent/driverModeAgent/targetExtractor";
import { SpinnerDots } from "../sprites";

// Color palette
const greenBullet = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);

interface EndpointSidebarProps {
  endpoints: DiscoveredEndpoint[];
  focusedIndex: number;
  reconStatus: 'idle' | 'running' | 'completed';
  onSelectEndpoint: (endpoint: DiscoveredEndpoint) => void;
}

export default function EndpointSidebar({
  endpoints,
  focusedIndex,
  reconStatus,
  onSelectEndpoint,
}: EndpointSidebarProps) {
  return (
    <box
      flexDirection="column"
      width="35%"
      border
      borderColor={focusedIndex >= 0 ? greenBullet : dimText}
      padding={1}
      gap={1}
    >
      <text fg={focusedIndex >= 0 ? creamText : dimText}>
        Discovered Endpoints ({endpoints.length})
      </text>

      {reconStatus === 'running' && (
        <box paddingTop={1} paddingBottom={1}>
          <SpinnerDots label="Discovering..." fg="green" />
        </box>
      )}

      {reconStatus === 'idle' && endpoints.length === 0 && (
        <text fg={dimText}>Recon will start automatically...</text>
      )}

      {reconStatus === 'completed' && endpoints.length === 0 && (
        <text fg={dimText}>No endpoints discovered.</text>
      )}

      <scrollbox flexGrow={1}>
        {endpoints.map((endpoint, index) => (
          <EndpointItem
            key={endpoint.id}
            endpoint={endpoint}
            index={index}
            focused={focusedIndex === index}
            onSelect={() => onSelectEndpoint(endpoint)}
          />
        ))}
      </scrollbox>

      {endpoints.length > 0 && (
        <text fg={dimText}>[Enter] to spawn agent</text>
      )}
    </box>
  );
}

/**
 * Individual endpoint item
 */
function EndpointItem({
  endpoint,
  index,
  focused,
  onSelect,
}: {
  endpoint: DiscoveredEndpoint;
  index: number;
  focused: boolean;
  onSelect: () => void;
}) {
  // Truncate URL for display
  const displayUrl = endpoint.url.length > 40
    ? endpoint.url.substring(0, 37) + '...'
    : endpoint.url;

  // Truncate objective for display
  const displayObjective = endpoint.suggestedObjective.length > 50
    ? endpoint.suggestedObjective.substring(0, 47) + '...'
    : endpoint.suggestedObjective;

  return (
    <box
      flexDirection="column"
      marginBottom={1}
      border={["left"]}
      borderColor={focused ? greenBullet : dimText}
      paddingLeft={1}
    >
      <text fg={focused ? creamText : dimText}>
        <span fg={greenBullet}>@{index} </span>
        {endpoint.method} {displayUrl}
      </text>
      <text fg={dimText}>
        └─ {displayObjective}
      </text>
    </box>
  );
}
