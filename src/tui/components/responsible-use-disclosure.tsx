import { useKeyboard } from "@opentui/react";

export function ResponsibleUseDisclosure({
  onAccept,
}: {
  onAccept: () => void;
}) {
    useKeyboard((key) => {
        // Enter key accepts the policy
        if (key.name === "return" || key.name === "enter") {
        onAccept();
        }
    });

    return (
      <box flexDirection="column" gap={1}>
        <text fg="yellow">IMPORTANT: Read Before Use</text>
        <text fg="white">
          This penetration testing tool is designedfor AUTHORIZED security
          testing only.
        </text>
        <box flexDirection="column" marginBottom={1}>
          <text fg="red">
            You MUST have explicit written permission to test any systems,
            networks, or applications
          </text>
        </box>
        <text fg="white">By accepting, you agree to:</text>
        <box flexDirection="column" marginLeft={2}>
          <text>• Only test systems you own or have authorization</text>
          <text fg="white">
            • Comply with all applicable laws and regulations
          </text>
          <text fg="white">• Use this tool ethically and responsibly</text>
          <text fg="white">• Not cause harm or disruption to services</text>
          <text fg="white">• Document and report findings appropriately</text>
        </box>
        <box flexDirection="column">
          <text fg="red">
            Unauthorized access to computer systems is illegaland may result in
            criminal prosecution.
          </text>
        </box>
        <box>
          <text fg="white">
            Press <span fg="green">ENTER</span> to accept and continue
          </text>
        </box>
      </box>
  );
}