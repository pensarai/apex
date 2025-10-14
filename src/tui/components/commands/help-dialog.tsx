import { useEffect, useMemo, useState } from "react";
import AlertDialog from "../alert-dialog";
import { useCommand } from "../../command-provider";
import { useRoute } from "../../context/route";

export default function HelpDialog() {
  const { commands } = useCommand();
  const route = useRoute();

  const [open, setOpen] = useState(false);

  useEffect(() => {
    if(route.data.type === "base" && route.data.path === "help") {
      setOpen(true);
    } else {
      setOpen(false);
    }
  }, [route]);

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
      open={open}
      onClose={() => setOpen(false)}
    />
  );
}
