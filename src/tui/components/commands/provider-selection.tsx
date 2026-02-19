import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import { useState } from "react";
import { useRoute } from "../../context/route";
import { useConfig } from "../../context/config";
import {
  AVAILABLE_PROVIDERS,
  getConfiguredProviders,
  type ProviderType,
} from "../../../core/providers";
import { useTheme } from "../../theme";

interface ProviderSelectionProps {
  onProviderSelected: (providerId: ProviderType) => void;
  onClose: () => void;
}

export default function ProviderSelection({
  onProviderSelected,
  onClose,
}: ProviderSelectionProps) {
  const { colors } = useTheme();
  const route = useRoute();
  const _config = useConfig();
  const [highlightedIndex, setHighlightedIndex] = useState(0);

  const configuredProviders = getConfiguredProviders(_config.data);

  useKeyboard((key) => {
    // Escape - Close provider selection
    if (key.name === "escape") {
      onClose();
      return;
    }

    // Arrow Up - Previous provider
    if (key.name === "up") {
      setHighlightedIndex((prev) =>
        prev > 0 ? prev - 1 : AVAILABLE_PROVIDERS.length - 1,
      );
      return;
    }

    // Arrow Down - Next provider
    if (key.name === "down") {
      setHighlightedIndex((prev) =>
        prev < AVAILABLE_PROVIDERS.length - 1 ? prev + 1 : 0,
      );
      return;
    }

    // Enter - Select provider
    if (key.name === "return") {
      const selected = AVAILABLE_PROVIDERS[highlightedIndex];
      if (selected) {
        onProviderSelected(selected.id);
      }
      return;
    }
  });

  return (
    <box
      position="absolute"
      top={0}
      left={0}
      zIndex={1000}
      width="100%"
      height="100%"
      justifyContent="center"
      alignItems="center"
      backgroundColor={"transparent"}
    >
      <box
        width={70}
        maxHeight="80%"
        border={true}
        borderColor={colors.primary}
        backgroundColor="black"
        flexDirection="column"
        padding={2}
      >
        {/* Header */}
        <box
          flexDirection="row"
          justifyContent="space-between"
          marginBottom={2}
        >
          <text fg={colors.primary}>Select provider</text>
          <text fg={colors.textMuted}>esc</text>
        </box>

        {/* Provider List */}
        <scrollbox
          style={{
            rootOptions: {
              width: "100%",
              flexGrow: 1,
              flexShrink: 1,
              overflow: "hidden",
            },
            wrapperOptions: {
              overflow: "hidden",
            },
            contentOptions: {
              flexDirection: "column",
              gap: 1,
            },
            scrollbarOptions: {
              trackOptions: {
                foregroundColor: colors.primary,
                backgroundColor: RGBA.fromInts(40, 40, 40, 255),
              },
            },
          }}
        >
          {/* Popular providers section */}
          <text fg={colors.textMuted} marginTop={1} marginBottom={1}>
            Popular providers
          </text>

          {AVAILABLE_PROVIDERS.map((provider, index) => {
            const isHighlighted = index === highlightedIndex;
            const configured = configuredProviders.find(
              (p) => p.id === provider.id,
            )?.configured;

            return (
              <box
                key={provider.id}
                flexDirection="row"
                gap={1}
                paddingLeft={1}
                paddingRight={1}
                backgroundColor={
                  isHighlighted ? RGBA.fromInts(0, 80, 0, 100) : undefined
                }
                onMouseDown={() => onProviderSelected(provider.id)}
              >
                <text fg={isHighlighted ? colors.primary : colors.text} flexGrow={1}>
                  {provider.name}{" "}
                  {provider.description ? (
                    <span fg={colors.textMuted}>({provider.description})</span>
                  ) : null}
                </text>
                {configured ? <text fg={colors.primary}>✓</text> : null}
              </box>
            );
          })}
        </scrollbox>

        {/* Footer help text */}
        <box marginTop={2}>
          <text fg={colors.textMuted}>
            <span fg={colors.primary}>[↑↓]</span> Navigate ·{" "}
            <span fg={colors.primary}>[ENTER]</span> Select ·{" "}
            <span fg={colors.primary}>[ESC]</span> Close
          </text>
        </box>
      </box>
    </box>
  );
}
