import { useKeyboard } from "@opentui/react";
import { useColors } from "../theme";

export function ResponsibleUseDisclosure({
  onAccept,
}: {
  onAccept: () => void;
}) {
    const colors = useColors();
    useKeyboard((key) => {
        // Enter key accepts the policy
        if (key.name === "return" || key.name === "enter") {
        onAccept();
        }
    });

    return (
      <box flexDirection="column" gap={1}>
        <text fg={colors.yellowText}>IMPORTANT: Read Before Use</text>
        <text fg={colors.primaryText}>
          This penetration testing tool is designedfor AUTHORIZED security
          testing only.
        </text>
        <box flexDirection="column" marginBottom={1}>
          <text fg={colors.redText}>
            You MUST have explicit written permission to test any systems,
            networks, or applications
          </text>
        </box>
        <text fg={colors.primaryText}>By accepting, you agree to:</text>
        <box flexDirection="column" marginLeft={2}>
          <text>• Only test systems you own or have authorization</text>
          <text fg={colors.primaryText}>
            • Comply with all applicable laws and regulations
          </text>
          <text fg={colors.primaryText}>• Use this tool ethically and responsibly</text>
          <text fg={colors.primaryText}>• Not cause harm or disruption to services</text>
          <text fg={colors.primaryText}>• Document and report findings appropriately</text>
        </box>
        <box flexDirection="column">
          <text fg={colors.redText}>
            Unauthorized access to computer systems is illegaland may result in
            criminal prosecution.
          </text>
        </box>
        <box>
          <text fg={colors.primaryText}>
            Press <span fg={colors.greenAccent}>ENTER</span> to accept and continue
          </text>
        </box>
      </box>
  );
}