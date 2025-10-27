import { useEffect, useState, useRef } from "react";
import { useKeyboard } from "@opentui/react";

interface LogEntry {
  timestamp: Date;
  level: "log" | "error" | "warn" | "info";
  message: string;
}

export default function DebugPanel() {
  const [isVisible, setIsVisible] = useState(false);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [autoScroll, setAutoScroll] = useState(true);
  const logContainerRef = useRef<HTMLElement>(null);

  // Intercept console methods
  useEffect(() => {
    const originalLog = console.log;
    const originalError = console.error;
    const originalWarn = console.warn;
    const originalInfo = console.info;

    const addLog = (level: LogEntry["level"], args: any[]) => {
      const message = args
        .map((arg) => {
          if (typeof arg === "object") {
            try {
              return JSON.stringify(arg, null, 2);
            } catch {
              return String(arg);
            }
          }
          return String(arg);
        })
        .join(" ");

      setLogs((prev) => [
        ...prev,
        {
          timestamp: new Date(),
          level,
          message,
        },
      ]);
    };

    console.log = (...args: any[]) => {
      originalLog(...args);
      addLog("log", args);
    };

    console.error = (...args: any[]) => {
      originalError(...args);
      addLog("error", args);
    };

    console.warn = (...args: any[]) => {
      originalWarn(...args);
      addLog("warn", args);
    };

    console.info = (...args: any[]) => {
      originalInfo(...args);
      addLog("info", args);
    };

    return () => {
      console.log = originalLog;
      console.error = originalError;
      console.warn = originalWarn;
      console.info = originalInfo;
    };
  }, []);

  // Handle Ctrl+K to toggle and Ctrl+L to clear
  useKeyboard((key) => {
    if (key.ctrl && key.name === "k") {
      setIsVisible((prev) => !prev);
      return;
    }

    if (isVisible && key.ctrl && key.name === "l") {
      setLogs([]);
      return;
    }
  });

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (autoScroll && logContainerRef.current) {
      // Scroll is handled by limiting the display to last N logs
    }
  }, [logs, autoScroll]);

  if (!isVisible) {
    return null;
  }

  const getLevelColor = (level: LogEntry["level"]) => {
    switch (level) {
      case "error":
        return "red";
      case "warn":
        return "yellow";
      case "info":
        return "cyan";
      default:
        return "white";
    }
  };

  const getLevelLabel = (level: LogEntry["level"]) => {
    switch (level) {
      case "error":
        return "[ERR]";
      case "warn":
        return "[WRN]";
      case "info":
        return "[INF]";
      default:
        return "[LOG]";
    }
  };

  return (
    <box
      position="absolute"
      bottom={0}
      left={0}
      width="100%"
      height="100%"
      backgroundColor="black"
      flexDirection="column"
      padding={1}
    >
      {/* Header */}
      <box
        width="100%"
        justifyContent="space-between"
        borderStyle="rounded"
        borderColor="cyan"
        padding={1}
      >
        <text fg="cyan">
          Debug Console ({logs.length} logs)
        </text>
        <text fg="gray">
          Ctrl+K to close | Ctrl+L to clear
        </text>
      </box>

      {/* Log display */}
      <scrollbox
        style={{
          rootOptions: {
            width: "100%",
            maxWidth: "100%",
            flexGrow: 1,
            flexShrink: 1,
            marginTop: 1,
            overflow: "hidden",
          },
          wrapperOptions: {
            overflow: "hidden",
            borderStyle: "rounded",
            borderColor: "gray",
          },
          contentOptions: {
            paddingLeft: 1,
            paddingRight: 1,
            gap: 0,
            flexGrow: 1,
            flexDirection: "column",
          },
          scrollbarOptions: {
            trackOptions: {
              foregroundColor: "cyan",
            },
          },
        }}
        stickyScroll={autoScroll}
        stickyStart="bottom"
        focused={isVisible}
      >
        {logs.length === 0 ? (
          <box>
            <text fg="gray">No logs yet...</text>
          </box>
        ) : (
          logs.map((log, index) => {
            const timeStr = log.timestamp.toLocaleTimeString("en-US", {
              hour12: false,
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
              fractionalSecondDigits: 3,
            });

            const logLine = `${timeStr} ${getLevelLabel(log.level)} ${log.message}`;

            return (
              <box key={index} width="100%">
                <text fg={getLevelColor(log.level)}>{logLine}</text>
              </box>
            );
          })
        )}
      </scrollbox>

      {/* Footer */}
      <box width="100%" justifyContent="center" marginTop={1}>
        <text fg="gray">
          Showing all {logs.length} logs (scroll with mouse/trackpad)
        </text>
      </box>
    </box>
  );
}