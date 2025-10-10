import { useAgent } from "../agentProvider";
import { SpinnerDots } from "./sprites";

export default function Header() {
  const { thinking } = useAgent();

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
      {thinking && <SpinnerDots label="Thinking..." fg="green" />}
    </box>
  );
}
