import type { InputProps } from "@opentui/react";

export default function Input(opts: InputProps & { label: string }) {
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
      <text fg="green">{opts.label}</text>
      <input
        paddingLeft={1}
        focused={true}
        backgroundColor="black"
        value={opts.value}
        placeholder={opts.placeholder}
        width={60}
        {...opts}
      />
    </box>
  );
}
