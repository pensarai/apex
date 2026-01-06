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

  const closeAlert = () => {
    setOpen(false);
    route.navigate({
      type: "base",
      path: "home"
    });
  }

  const message = useMemo(() => {
    // Generate commands list with options (aliases hidden but still work)
    const commandsList = commands
      .map((cmd) => {
        let line = ` /${cmd.name}: ${cmd.description || "No description"}`;

        // Add options if present
        if (cmd.options?.length) {
          const optionLines = cmd.options.map((opt) => {
            const valueHint = opt.valueHint ? ` ${opt.valueHint}` : "";
            return `   ${opt.name}${valueHint}  ${opt.description}`;
          });
          line += "\n" + optionLines.join("\n");
        }

        return line;
      })
      .join("\n\n");

    return `Available Commands:\n\n${commandsList}`;
  }, [commands]);

  return (
    <AlertDialog
      title="Help"
      message={message}
      open={open}
      onClose={closeAlert}
    />
  );
}