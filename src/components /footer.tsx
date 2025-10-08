interface FooterProps {
  cwd?: string;
  showExitWarning?: boolean;
}

export default function Footer({
  cwd = process.cwd(),
  showExitWarning = false,
}: FooterProps) {
  cwd = "~/" + cwd.split("/").pop() || "";

  const hotkeys = [
    { key: "Tab", label: "Next" },
    { key: "Shift+Tab", label: "Prev" },
    { key: "Ctrl+C", label: "Clear/Exit" },
  ];

  return (
    <box
      flexDirection="row"
      justifyContent="space-between"
      width="100%"
      border={true}
      borderColor="green"
    >
      <box flexDirection="row" gap={1}>
        <text fg="green">[CWD]</text>
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
