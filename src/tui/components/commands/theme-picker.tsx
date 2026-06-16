/**
 * Theme Picker — /themes command
 *
 * Scrollable list of all registered themes with live preview.
 * Navigating applies the theme temporarily; Enter confirms and persists.
 * Escape reverts to the previous theme.
 */

import { useKeyboard } from "@opentui/react";
import { useCallback, useRef, useState } from "react";
import { config } from "../../../core/config";
import { Dialog } from "../../context/dialog";
import { useDimensions } from "../../context/dimensions";
import { useTheme } from "../../theme";
import DialogLayout from "../dialog-layout";

interface ThemePickerProps {
  onClose: () => void;
}

export default function ThemePicker({ onClose }: ThemePickerProps) {
  const dimensions = useDimensions();
  const {
    colors,
    theme,
    mode,
    availableThemes,
    setTheme,
    toggleMode,
    setMode,
    transparent,
    toggleTransparent,
  } = useTheme();

  const [selectedIndex, setSelectedIndex] = useState(() =>
    Math.max(0, availableThemes.indexOf(theme.name)),
  );
  const originalThemeRef = useRef(theme.name);
  const originalModeRef = useRef(mode);
  const originalTransparentRef = useRef(transparent);

  const handleClose = useCallback(() => {
    // Revert previews to their state when the dialog opened
    setTheme(originalThemeRef.current);
    setMode(originalModeRef.current);
    if (transparent !== originalTransparentRef.current) toggleTransparent();
    onClose();
  }, [setTheme, setMode, transparent, toggleTransparent, onClose]);

  const handleConfirm = useCallback(async () => {
    const currentThemeName = availableThemes[selectedIndex];
    if (currentThemeName) {
      await config.update({ theme: currentThemeName });
    }
    await config.update({ transparentBackground: transparent });
    onClose();
  }, [availableThemes, selectedIndex, transparent, onClose]);

  useKeyboard((evt) => {
    // Modal dialog — consume all keystrokes to prevent leaking to components underneath
    evt.preventDefault();

    if (evt.name === "escape") {
      handleClose();
      return;
    }

    if (evt.name === "return") {
      handleConfirm();
      return;
    }

    if (evt.name === "up" || (evt.name === "k" && !evt.ctrl)) {
      setSelectedIndex((prev) => {
        const next = prev <= 0 ? availableThemes.length - 1 : prev - 1;
        if (availableThemes[next]) setTheme(availableThemes[next]);
        return next;
      });
      return;
    }

    if (evt.name === "down" || (evt.name === "j" && !evt.ctrl)) {
      setSelectedIndex((prev) => {
        const next = prev >= availableThemes.length - 1 ? 0 : prev + 1;
        if (availableThemes[next]) setTheme(availableThemes[next]);
        return next;
      });
      return;
    }

    // Toggle dark/light mode with 'm' or 't'
    if (evt.name === "m" || evt.name === "t") {
      toggleMode();
      // Persist mode change
      const newMode = mode === "dark" ? "light" : "dark";
      config.update({ themeMode: newMode });
      return;
    }

    if (evt.name === "b") {
      toggleTransparent();
      return;
    }
  });

  const panelWidth = Math.min(50, dimensions.width - 4);
  const panelHeight = Math.min(
    availableThemes.length + 6,
    dimensions.height - 4,
  );

  // Calculate visible window for scrolling
  const listHeight = panelHeight - 5; // header + footer + borders
  const scrollOffset = Math.max(
    0,
    Math.min(
      selectedIndex - Math.floor(listHeight / 2),
      availableThemes.length - listHeight,
    ),
  );
  const visibleThemes = availableThemes.slice(
    scrollOffset,
    scrollOffset + listHeight,
  );

  return (
    <Dialog size="large" onClose={handleClose}>
      <DialogLayout
        title="Themes"
        escLabel="cancel"
        footerActions={[
          { key: "Enter", label: "select", variant: "primary" },
          { key: "M", label: "toggle mode" },
          { key: "B", label: "transparency" },
        ]}
      >
        {/* Mode indicator */}
        <box marginBottom={1}>
          <text fg={colors.textMuted}>
            mode: {mode} · transparent: {transparent ? "on" : "off"}
          </text>
        </box>

        {/* Separator */}
        <box width="100%" height={1}>
          <text fg={colors.border}>{"─".repeat(panelWidth - 2)}</text>
        </box>

        {/* Theme List */}
        <box flexDirection="column" flexGrow={1}>
          {visibleThemes.map((themeName) => {
            const actualIndex = availableThemes.indexOf(themeName);
            const isSelected = actualIndex === selectedIndex;
            const isCurrent = themeName === originalThemeRef.current;

            return (
              <box key={themeName} flexDirection="row">
                <text fg={isSelected ? colors.primary : colors.textMuted}>
                  {isSelected ? "❯ " : "  "}
                </text>
                <text fg={isSelected ? colors.primary : colors.text}>
                  {themeName}
                </text>
                {isCurrent && <text fg={colors.textMuted}> (current)</text>}
              </box>
            );
          })}
        </box>

        {/* Separator */}
        <box width="100%" height={1}>
          <text fg={colors.border}>{"─".repeat(panelWidth - 2)}</text>
        </box>
      </DialogLayout>
    </Dialog>
  );
}
