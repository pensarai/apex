import { useAgent } from "../context/agent";
import { AgentStatus } from "./footer";
import { useTheme } from "../theme";

export default function Header() {
  const { colors } = useTheme();
  const { thinking } = useAgent();
  if (!thinking) return null;

  return (
    <box
      border={true}
      width="100%"
      maxWidth="100%"
      flexShrink={0}
      borderColor={colors.primary}
      flexDirection="row"
      justifyContent="space-between"
    >
      <text fg={colors.primary}>Pensar</text>
      <AgentStatus />
    </box>
  );
}
