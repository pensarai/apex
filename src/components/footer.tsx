import os from "os";

interface FooterProps {
  cwd?: string;
  showExitWarning?: boolean;
}

export default function Footer({
  cwd = process.cwd(),
  showExitWarning = false,
}: FooterProps) {
  cwd = "~" + cwd.split(os.homedir()).pop() || "";

  const hotkeys = [{ key: "Ctrl+C", label: "Clear/Exit" }];

  return (
    <box
      flexDirection="row"
      justifyContent="space-between"
      width="100%"
      maxWidth="100%"
      flexShrink={0}
      border={true}
      borderColor="green"
    >
      <box flexDirection="row" gap={1}>
        <text fg="gray">{cwd}</text>
      </box>
      {showExitWarning ? (
        <box flexDirection="row" gap={1}>
          <text fg="yellow">⚠ Press Ctrl+C again to exit</text>
        </box>
      ) : (
        <box flexDirection="row" gap={2}>
          {hotkeys.map((hotkey, index) => (
            <box key={index} flexDirection="row" gap={1}>
              <text fg="green">[{hotkey.key}]</text>
              <text fg="gray">{hotkey.label}</text>
            </box>
          ))}
        </box>
      )}
    </box>
  );
}
