import { useKeyboard } from "@opentui/react";
import { useState } from "react";
import {
  AVAILABLE_PROVIDERS,
  getConfiguredProviders,
  type Provider,
  type ProviderType,
} from "../../../core/providers";
import { useConfig } from "../../context/config";
import { Dialog } from "../../context/dialog";
import { useRoute } from "../../context/route";
import { useTheme } from "../../theme";
import DialogLayout from "../dialog-layout";

interface ProviderSelectionProps {
  providers?: Provider[];
  onProviderSelected: (providerId: ProviderType) => void;
  onClose: () => void;
}

export default function ProviderSelection({
  providers,
  onProviderSelected,
  onClose,
}: ProviderSelectionProps) {
  const { colors } = useTheme();
  const route = useRoute();
  const _config = useConfig();
  const [highlightedIndex, setHighlightedIndex] = useState(0);

  const providerList = providers ?? AVAILABLE_PROVIDERS;
  const configuredProviders = getConfiguredProviders(_config.data);

  useKeyboard((key) => {
    key.preventDefault();

    if (key.name === "escape") {
      onClose();
      return;
    }

    if (key.name === "up") {
      setHighlightedIndex((prev) =>
        prev > 0 ? prev - 1 : providerList.length - 1,
      );
      return;
    }

    if (key.name === "down") {
      setHighlightedIndex((prev) =>
        prev < providerList.length - 1 ? prev + 1 : 0,
      );
      return;
    }

    if (key.name === "return") {
      const selected = providerList[highlightedIndex];
      if (selected) {
        onProviderSelected(selected.id);
      }
      return;
    }
  });

  return (
    <Dialog size="large" onClose={onClose}>
      <DialogLayout
        title="Select provider"
        flushRight
        footerActions={[{ key: "Enter", label: "select", variant: "primary" }]}
      >
        {/* Provider List */}
        <scrollbox
          style={{
            rootOptions: {
              flexShrink: 1,
              width: "100%",
              maxHeight: providerList.length * 2,
            },
            contentOptions: {
              flexDirection: "column",
              gap: 1,
            },
            scrollbarOptions: {
              trackOptions: {
                foregroundColor: colors.textMuted,
                backgroundColor: colors.backgroundElement,
              },
            },
          }}
          stickyScroll={false}
          focused={true}
        >
          {providerList.map((provider, index) => {
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
                  isHighlighted ? colors.backgroundSelected : undefined
                }
                onMouseDown={() => onProviderSelected(provider.id)}
              >
                <text
                  fg={isHighlighted ? colors.primary : colors.text}
                  flexGrow={1}
                >
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
      </DialogLayout>
    </Dialog>
  );
}
