import { useState } from "react";
import Autocomplete from "./components/autocomplete";
import { useCommand } from "./command-provider";

interface CommandInputProps {
  focused?: boolean;
  inputKey?: number;
}

export default function CommandInput({
  focused = true,
  inputKey = 0,
}: CommandInputProps) {
  const [command, setCommand] = useState("");
  const { autocompleteOptions, executeCommand } = useCommand();

  const handleSubmit = async (value: string) => {
    const raw = value ?? "";
    await executeCommand(raw);
    setCommand("");
  };

  return (
    <box
      flexDirection="column"
      justifyContent="center"
      width={60}
      flexGrow={1}
      gap={2}
    >
      <Autocomplete
        key={inputKey}
        label="Command"
        value={command}
        placeholder="Enter a command or / for suggestions..."
        focused={focused}
        options={autocompleteOptions}
        onInput={(value) => setCommand(value)}
        onSubmit={handleSubmit}
      />
    </box>
  );
}
