import { useKeyboard } from "@opentui/react";
import { useRef } from "react";
import { useTheme } from "../theme";

export function ResponsibleUseDisclosure({
  onAccept,
}: {
  onAccept: () => void;
}) {
  const processedRef = useRef(false);

  useKeyboard((key) => {
    // Enter key accepts the policy - prevent duplicate processing
    if (
      (key.name === "return" || key.name === "enter") &&
      !processedRef.current
    ) {
      processedRef.current = true;
      // Small delay to ensure state updates process correctly
      setTimeout(() => {
        onAccept();
      }, 50);
    }
  });

  const { colors } = useTheme();

  return (
    <box flexDirection="column" gap={1}>
      <text fg={colors.warning}>IMPORTANT: Read Before Use</text>
      <text fg={colors.text}>
        This penetration testing tool is designedfor AUTHORIZED security testing
        only.
      </text>
      <box flexDirection="column" marginBottom={1}>
        <text fg={colors.error}>
          You MUST have explicit written permission to test any systems,
          networks, or applications
        </text>
      </box>
      <text fg={colors.text}>By accepting, you agree to:</text>
      <box flexDirection="column" marginLeft={2}>
        <text>• Only test systems you own or have authorization</text>
        <text fg={colors.text}>
          • Comply with all applicable laws and regulations
        </text>
        <text fg={colors.text}>• Use this tool ethically and responsibly</text>
        <text fg={colors.text}>• Not cause harm or disruption to services</text>
        <text fg={colors.text}>• Document and report findings appropriately</text>
      </box>
      <box flexDirection="column">
        <text fg={colors.error}>
          Unauthorized access to computer systems is illegaland may result in
          criminal prosecution.
        </text>
      </box>
      <box>
        <text fg={colors.text}>
          Press <span fg={colors.primary}>ENTER</span> to accept and continue
        </text>
      </box>
    </box>
  );
}
