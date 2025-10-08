import { useMemo } from "react";
import AlertDialog from "./alert-dialog";
import { useCommand } from "../command-provider";

export default function HelpDialog({
  helpOpen,
  closeHelp,
}: {
  helpOpen: boolean;
  closeHelp: () => void;
}) {
  const { commands } = useCommand();

  const message = useMemo(() => {
    // Generate commands list
    const commandsList = commands
      .map((cmd) => {
        const aliases = cmd.aliases?.length
          ? ` (${cmd.aliases.map((a) => `/${a}`).join(", ")})`
          : "";
        return ` - /${cmd.name}${aliases}: ${
          cmd.description || "No description"
        }`;
      })
      .join("\n");

    return `Available Commands:\n${commandsList}`;
  }, [commands]);

  return (
    <AlertDialog
      title="Help"
      message={message}
      open={helpOpen}
      onClose={closeHelp}
    />
  );
}
