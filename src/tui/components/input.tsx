import { forwardRef } from "react";
import type { InputProps } from "@opentui/react";
import type { InputRenderable } from "@opentui/core";
import { useColors } from "../theme";

interface InputComponentProps extends InputProps {
  label: string;
  description?: string;
}

const Input = forwardRef<InputRenderable, InputComponentProps>(function Input(
  opts,
  ref
) {
  const { label, focused = true, description, ...inputProps } = opts;
  const colors = useColors();

  return (
    <box
      width="100%"
      backgroundColor="transparent"
      flexDirection="column"
      paddingBottom={1}
      // paddingTop={1}
      border={['left']}
      borderColor={colors.greenAccent}
    >
      <text fg={colors.greenAccent}>{label}</text>
      {description && <text fg={colors.secondaryText}>{description}</text>}
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
