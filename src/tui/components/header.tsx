import { useAgent } from "../context/agent";
import { AgentStatus } from "./footer";
import { SpinnerDots } from "./sprites";

export default function Header() {
  const { thinking } = useAgent();
  if (!thinking) return null;

  return (
    <box
      border={true}
      width="100%"
      maxWidth="100%"
      flexShrink={0}
      borderColor="green"
      flexDirection="row"
      justifyContent="space-between"
    >
      <text fg="green">Pensar</text>
      <AgentStatus />
    </box>
  );
}
