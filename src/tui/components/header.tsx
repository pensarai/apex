import { useAgent } from "../context/agent";
import { AgentStatus } from "./footer";
import { SpinnerDots } from "./sprites";
import { useColors } from "../theme";

export default function Header() {
  const { thinking } = useAgent();
  const colors = useColors();
  if (!thinking) return null;

  return (
    <box
      border={true}
      width="100%"
      maxWidth="100%"
      flexShrink={0}
      borderColor={colors.greenAccent}
      flexDirection="row"
      justifyContent="space-between"
    >
      <text fg={colors.greenAccent}>Pensar</text>
      <AgentStatus />
    </box>
  );
}
