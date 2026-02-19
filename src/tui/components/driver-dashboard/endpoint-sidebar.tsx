/**
 * Endpoint Sidebar
 *
 * Shows discovered endpoints from recon with ability to spawn agents.
 */

import type { DiscoveredEndpoint } from "../../../core/agent/driverModeAgent/targetExtractor";
import { SpinnerDots } from "../sprites";
import { useTheme } from "../../theme";

interface EndpointSidebarProps {
  endpoints: DiscoveredEndpoint[];
  focusedIndex: number;
  reconStatus: "idle" | "running" | "completed";
  onSelectEndpoint: (endpoint: DiscoveredEndpoint) => void;
}

export default function EndpointSidebar({
  endpoints,
  focusedIndex,
  reconStatus,
  onSelectEndpoint,
}: EndpointSidebarProps) {
  const { colors } = useTheme();
  return (
    <box
      flexDirection="column"
      width="35%"
      border
      borderColor={focusedIndex >= 0 ? colors.primary : colors.textMuted}
      padding={1}
      gap={1}
    >
      <text fg={focusedIndex >= 0 ? colors.text : colors.textMuted}>
        Discovered Endpoints ({endpoints.length})
      </text>

      {reconStatus === "running" && (
        <box paddingTop={1} paddingBottom={1}>
          <SpinnerDots label="Discovering..." fg={colors.primary} />
        </box>
      )}

      {reconStatus === "idle" && endpoints.length === 0 && (
        <text fg={colors.textMuted}>Recon will start automatically...</text>
      )}

      {reconStatus === "completed" && endpoints.length === 0 && (
        <text fg={colors.textMuted}>No endpoints discovered.</text>
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

      {endpoints.length > 0 && <text fg={colors.textMuted}>[Enter] to spawn agent</text>}
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
  const { colors } = useTheme();
  // Truncate URL for display
  const displayUrl =
    endpoint.url.length > 40
      ? endpoint.url.substring(0, 37) + "..."
      : endpoint.url;

  // Truncate objective for display
  const displayObjective =
    endpoint.suggestedObjective.length > 50
      ? endpoint.suggestedObjective.substring(0, 47) + "..."
      : endpoint.suggestedObjective;

  return (
    <box
      flexDirection="column"
      marginBottom={1}
      border={["left"]}
      borderColor={focused ? colors.primary : colors.textMuted}
      paddingLeft={1}
    >
      <text fg={focused ? colors.text : colors.textMuted}>
        <span fg={colors.primary}>@{index} </span>
        {endpoint.method} {displayUrl}
      </text>
      <text fg={colors.textMuted}>└─ {displayObjective}</text>
    </box>
  );
}
