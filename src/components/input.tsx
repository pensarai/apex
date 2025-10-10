import type { InputProps } from "@opentui/react";

export default function Input(
  opts: InputProps & { label: string; description?: string }
) {
  const { label, focused = true, description, ...inputProps } = opts;

  return (
    <box
      border={true}
      width="100%"
      borderStyle="heavy"
      backgroundColor="black"
      borderColor="green"
      flexDirection="column"
    >
      <text fg="green">{label}</text>
      {description && <text fg="gray">{description}</text>}
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
