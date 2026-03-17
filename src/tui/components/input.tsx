import { forwardRef } from "react";
import type { InputProps } from "@opentui/react";
import type { InputRenderable, KeyBinding } from "@opentui/core";
import { useTheme } from "../theme";

interface InputComponentProps extends InputProps {
  label: string;
  description?: string;
  keyBindings?: KeyBinding[];
}

const Input = forwardRef<InputRenderable, InputComponentProps>(
  function Input(opts, ref) {
    const { colors } = useTheme();
    const {
      label,
      focused = true,
      description,
      keyBindings,
      ...inputProps
    } = opts;

    return (
      <box
        width="100%"
        backgroundColor="transparent"
        flexDirection="column"
        paddingBottom={1}
        // paddingTop={1}
        border={["left"]}
        borderColor={colors.primary}
      >
        <text fg={colors.primary}>{label}</text>
        {description && <text fg={colors.textMuted}>{description}</text>}
        <input
          ref={ref}
          paddingLeft={1}
          backgroundColor="transparent"
          focused={focused}
          cursorColor={colors.textMuted}
          textColor={colors.text}
          focusedTextColor={colors.text}
          keyBindings={keyBindings}
          {...inputProps}
        />
      </box>
    );
  },
);

export default Input;
