/**
 * Skills Dialog
 *
 * Dialog overlay displaying installed skills grouped by source, with token estimates.
 * Arrow keys to navigate, Enter for detail view, Escape to close.
 */

import { useState, useMemo, useEffect } from "react";
import { useKeyboard } from "@opentui/react";
import { useCommand } from "../../context/command";
import { useDimensions } from "../../context/dimensions";
import { useTheme } from "../../theme";
import { Dialog } from "../../context/dialog";
import type { SkillEntry, SkillSource } from "../../../core/skills/types";

/** Rough token estimate: ~4 chars per token */
function estimateTokens(text: string): number {
  return Math.round(text.length / 4);
}

const GROUP_LABELS: Record<SkillSource, string> = {
  project: "Project skills",
  user: "User skills",
};

const GROUP_ORDER: SkillSource[] = ["project", "user"];

interface SkillsDialogProps {
  onClose: () => void;
  initialSlug?: string;
}

export default function SkillsDialog({ onClose, initialSlug }: SkillsDialogProps) {
  const { colors } = useTheme();
  const { skillsRegistry } = useCommand();
  const dimensions = useDimensions();

  const [selectedIndex, setSelectedIndex] = useState(0);
  const [detailSkill, setDetailSkill] = useState<SkillEntry | null>(() => {
    if (initialSlug) {
      const entry = skillsRegistry.get(initialSlug);
      return entry ?? null;
    }
    return null;
  });

  // Load instructions on demand for the detail view
  const [detailInstructions, setDetailInstructions] = useState<string | null>(
    null,
  );

  useEffect(() => {
    if (!detailSkill) {
      setDetailInstructions(null);
      return;
    }
    let cancelled = false;
    skillsRegistry
      .readSkillContent(detailSkill.slug)
      .then(({ content }) => {
        if (!cancelled) setDetailInstructions(content);
      })
      .catch(() => {
        if (!cancelled) setDetailInstructions("(failed to load instructions)");
      });
    return () => {
      cancelled = true;
    };
  }, [detailSkill, skillsRegistry]);

  const allSkills = useMemo(() => skillsRegistry.list(), [skillsRegistry]);

  // Build grouped structure with flat index for keyboard nav
  const { groups, flatList } = useMemo(() => {
    const grouped: Record<string, SkillEntry[]> = {};
    for (const skill of allSkills) {
      const key = skill.source;
      (grouped[key] ??= []).push(skill);
    }

    const groups: Array<{ label: string; skills: SkillEntry[] }> = [];
    const flatList: SkillEntry[] = [];
    for (const key of GROUP_ORDER) {
      const skills = grouped[key];
      if (skills?.length) {
        groups.push({ label: GROUP_LABELS[key], skills });
        flatList.push(...skills);
      }
    }
    return { groups, flatList };
  }, [allSkills]);

  useKeyboard((evt) => {
    evt.preventDefault();

    // Detail view — escape/enter goes back to list
    if (detailSkill) {
      if (evt.name === "escape" || evt.name === "return") {
        setDetailSkill(null);
      }
      return;
    }

    switch (evt.name) {
      case "escape":
        onClose();
        break;

      case "up":
      case "k":
        evt.preventDefault();
        setSelectedIndex((prev) => (prev > 0 ? prev - 1 : flatList.length - 1));
        break;

      case "down":
      case "j":
        evt.preventDefault();
        setSelectedIndex((prev) => (prev < flatList.length - 1 ? prev + 1 : 0));
        break;

      case "return":
        evt.preventDefault();
        if (flatList[selectedIndex]) {
          setDetailSkill(flatList[selectedIndex]);
        }
        break;
    }
  });

  // Clamp index
  const safeIndex = Math.min(selectedIndex, flatList.length - 1);

  const panelWidth = Math.min(76, dimensions.width - 4);

  // ---------- Detail view ----------
  if (detailSkill) {
    const m = detailSkill.manifest;
    const instrText = detailInstructions ?? "";
    const instrTokens = estimateTokens(instrText);
    const descTokens = estimateTokens(m.description);
    const instrLines = instrText
      ? instrText.split("\n")
      : ["Loading instructions..."];

    return (
      <Dialog size="large" onClose={() => setDetailSkill(null)}>
        <box flexDirection="column" width="100%" padding={1}>
          {/* Header */}
          <box width="100%" flexDirection="row" justifyContent="space-between">
            <text>
              <span fg={colors.primary}>{detailSkill.slug}</span>
              {m.version && <span fg={colors.textMuted}> v{m.version}</span>}
            </text>
            <text fg={colors.textMuted}>
              {detailInstructions !== null
                ? `~${instrTokens + descTokens} tokens`
                : "loading..."}
            </text>
          </box>

          {/* Separator */}
          <box width="100%" height={1}>
            <text fg={colors.border}>{"─".repeat(panelWidth - 2)}</text>
          </box>

          {/* Metadata */}
          <box flexDirection="column">
            {m.tags && m.tags.length > 0 && (
              <text>
                <span fg={colors.textMuted}>Tags: </span>
                <span fg={colors.text}>{m.tags.join(", ")}</span>
              </text>
            )}
            <text>
              <span fg={colors.textMuted}>Source: </span>
              <span fg={colors.text}>{detailSkill.filePath}</span>
            </text>
            {detailSkill.scripts.length > 0 && (
              <text>
                <span fg={colors.textMuted}>Scripts: </span>
                <span fg={colors.text}>
                  {detailSkill.scripts.map((s) => s.name).join(", ")}
                </span>
              </text>
            )}
          </box>

          {/* Separator */}
          <box width="100%" height={1} marginTop={1}>
            <text fg={colors.border}>{"─".repeat(panelWidth - 2)}</text>
          </box>

          {/* Scrollable instructions */}
          <scrollbox
            style={{
              rootOptions: {
                flexGrow: 1,
                flexShrink: 1,
                width: "100%",
                marginTop: 0,
              },
              contentOptions: {
                paddingLeft: 1,
                paddingRight: 1,
                flexDirection: "column",
              },
            }}
            stickyScroll={false}
            focused={true}
          >
            {instrLines.map((line, i) => (
              <text key={i} fg={colors.text}>
                {line || " "}
              </text>
            ))}
          </scrollbox>

          {/* Separator */}
          <box width="100%" height={1}>
            <text fg={colors.border}>{"─".repeat(panelWidth - 2)}</text>
          </box>

          {/* Footer */}
          <box width="100%" flexDirection="row">
            <text fg={colors.textMuted}>
              [↑↓] scroll [esc] back
            </text>
          </box>
        </box>
      </Dialog>
    );
  }

  // ---------- List view ----------
  let flatIdx = 0;

  // Calculate visible window for scrolling
  const listHeight = Math.max(1, dimensions.height - 12);
  const scrollOffset = Math.max(
    0,
    Math.min(
      safeIndex - Math.floor(listHeight / 2),
      flatList.length - listHeight,
    ),
  );

  // Build visible items with group headers
  const visibleItems: Array<{ type: "header"; label: string } | { type: "skill"; skill: SkillEntry; index: number }> = [];
  let runningIdx = 0;
  for (const group of groups) {
    const groupStart = runningIdx;
    const groupEnd = runningIdx + group.skills.length;
    // Show header if any skill from this group is in the visible window
    if (groupEnd > scrollOffset && groupStart < scrollOffset + listHeight) {
      visibleItems.push({ type: "header", label: group.label });
    }
    for (const skill of group.skills) {
      if (runningIdx >= scrollOffset && runningIdx < scrollOffset + listHeight) {
        visibleItems.push({ type: "skill", skill, index: runningIdx });
      }
      runningIdx++;
    }
  }

  return (
    <Dialog size="large" onClose={onClose}>
      <box flexDirection="column" width="100%" padding={1}>
        {/* Header */}
        <box width="100%" flexDirection="row" justifyContent="space-between">
          <text fg={colors.primary}>Skills</text>
          <text fg={colors.textMuted}>
            {allSkills.length} skill{allSkills.length !== 1 ? "s" : ""}
          </text>
        </box>

        {/* Separator */}
        <box width="100%" height={1}>
          <text fg={colors.border}>{"─".repeat(panelWidth - 2)}</text>
        </box>

        {/* Skill list */}
        <box flexDirection="column" flexGrow={1}>
          {visibleItems.map((item, i) => {
            if (item.type === "header") {
              return (
                <text key={`h-${item.label}`} fg={colors.textMuted}>
                  {item.label}
                </text>
              );
            }
            const selected = item.index === safeIndex;
            return (
              <box key={item.skill.slug} flexDirection="row">
                <text fg={selected ? colors.primary : colors.textMuted}>
                  {selected ? "❯ " : "  "}
                </text>
                <text fg={selected ? colors.primary : colors.text}>
                  {item.skill.slug}
                </text>
                <text fg={colors.textMuted}>
                  {" "}· ~{estimateTokens(item.skill.manifest.description)} tokens
                </text>
              </box>
            );
          })}

          {allSkills.length === 0 && (
            <text fg={colors.textMuted}>
              No skills installed.
            </text>
          )}
        </box>

        {/* Separator */}
        <box width="100%" height={1}>
          <text fg={colors.border}>{"─".repeat(panelWidth - 2)}</text>
        </box>

        {/* Footer */}
        <box width="100%" flexDirection="row">
          <text fg={colors.textMuted}>
            [↑↓] browse [enter] details [esc] close
          </text>
        </box>
      </box>
    </Dialog>
  );
}
