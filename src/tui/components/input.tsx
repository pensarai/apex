import { forwardRef } from "react";
import type { InputProps } from "@opentui/react";
import type { InputRenderable } from "@opentui/core";

interface InputComponentProps extends InputProps {
  label: string;
  description?: string;
}

const Input = forwardRef<InputRenderable, InputComponentProps>(function Input(
  opts,
  ref
) {
  const { label, focused = true, description, ...inputProps } = opts;

  return (
    <box
      width="100%"
      backgroundColor="transparent"
      flexDirection="column"
      paddingBottom={1}
      // paddingTop={1}
      border={['left']}
      borderColor={'green'}
    >
      <text fg="green">{label}</text>
      {description && <text fg="gray">{description}</text>}
      <input
        ref={ref}
        paddingLeft={1}
        backgroundColor="transparent"
        focused={focused}
        {...inputProps}
      />
    </box>
  );
});

export default Input;
