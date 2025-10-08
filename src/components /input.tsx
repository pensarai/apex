import type { InputProps } from "@opentui/react";

export default function Input(opts: InputProps & { label: string }) {
  const { label, focused = true, ...inputProps } = opts;

  return (
    <box
      border={true}
      width="100%"
      borderStyle="heavy"
      backgroundColor="black"
      borderColor="green"
      flexDirection="column"
      justifyContent="center"
    >
      <text fg="green">{label}</text>
      <input
        paddingLeft={1}
        backgroundColor="black"
        width={60}
        focused={focused}
        {...inputProps}
      />
    </box>
  );
}
