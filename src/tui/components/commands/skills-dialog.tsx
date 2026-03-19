/**
 * Skills Dialog
 *
 * Full-page display of installed skills grouped by source, with token estimates.
 * Arrow keys to navigate, Enter for detail view, Escape to go back.
 * Matches the /models page layout.
 */

import { useState, useMemo, useEffect } from "react";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { useCommand } from "../../context/command";
import { useRoute } from "../../context/route";
import { useTheme } from "../../theme";
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

export default function SkillsDialog() {
  const { colors } = useTheme();
  const { skillsRegistry } = useCommand();
  const route = useRoute();
  const dimensions = useTerminalDimensions();

  // Auto-open detail view when navigated with a specific skill slug
  const initialSlug =
    route.data.type === "base" ? route.data.options?.skillSlug : undefined;

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

  const goHome = () => {
    route.navigate({ type: "base", path: "home" });
  };

  useKeyboard((evt) => {
    // Detail view — any key goes back to list
    if (detailSkill) {
      if (evt.name === "escape" || evt.name === "return") {
        evt.preventDefault();
        setDetailSkill(null);
      }
      return;
    }

    switch (evt.name) {
      case "escape":
        evt.preventDefault();
        goHome();
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
  const maxDescWidth = Math.max(20, dimensions.width - 12);

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
      <box
        flexDirection="column"
        width="100%"
        height="100%"
        paddingLeft={4}
        paddingTop={2}
      >
        {/* Header */}
        <text>
          <span fg={colors.primary}>█ </span>
          <span fg={colors.text}>{detailSkill.slug}</span>
          {m.version && <span fg={colors.textMuted}> v{m.version}</span>}
          <span fg={colors.textMuted}>
            {" "}
            ·{" "}
            {detailInstructions !== null
              ? `~${instrTokens + descTokens} tokens`
              : "loading..."}
          </span>
        </text>

        {/* Metadata row */}
        <box paddingLeft={2} marginTop={1} flexDirection="column">
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

        {/* Scrollable instructions */}
        <box paddingLeft={2} marginTop={1} flexDirection="column">
          <text fg={colors.textMuted}>Instructions:</text>
        </box>
        <scrollbox
          style={{
            rootOptions: {
              flexGrow: 1,
              flexShrink: 1,
              width: "100%",
              marginTop: 0,
            },
            contentOptions: {
              paddingLeft: 6,
              paddingRight: 2,
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

        {/* Footer */}
        <box marginTop={1} paddingBottom={1}>
          <text>
            <span fg={colors.primary}>█ </span>
            <span fg={colors.text}>[↑][↓]</span>
            <span fg={colors.textMuted}> scroll </span>
            <span fg={colors.text}>[ESC]</span>
            <span fg={colors.textMuted}> back</span>
          </text>
        </box>
      </box>
    );
  }

  // ---------- List view ----------
  let flatIdx = 0;

  return (
    <box flexDirection="column" width="100%" paddingLeft={4} paddingTop={2}>
      {/* Header */}
      <text>
        <span fg={colors.primary}>█ </span>
        <span fg={colors.text}>Skills</span>
      </text>
      <text>
        <span fg={colors.primary}>█ </span>
        <span fg={colors.textMuted}>
          {allSkills.length} skill{allSkills.length !== 1 ? "s" : ""}
        </span>
      </text>

      {/* Skill groups */}
      <box flexDirection="column" paddingLeft={2} marginTop={1}>
        {groups.map((group) => (
          <box key={group.label} flexDirection="column" marginTop={1}>
            <text fg={colors.textMuted}>{group.label}</text>
            {group.skills.map((skill) => {
              const idx = flatIdx++;
              const selected = idx === safeIndex;
              return (
                <text key={skill.slug}>
                  <span fg={selected ? colors.primary : colors.text}>
                    {selected ? "▸ " : "  "}
                    {skill.slug}
                  </span>
                  <span fg={colors.textMuted}>
                    {" "}
                    · ~{estimateTokens(skill.manifest.description)} description
                    tokens
                  </span>
                </text>
              );
            })}
          </box>
        ))}

        {allSkills.length === 0 && (
          <box marginTop={1}>
            <text fg={colors.textMuted}>
              No skills installed. Use `bunx skills add` to install skills.
            </text>
          </box>
        )}
      </box>

      {/* Footer */}
      <box flexDirection="column" marginTop={2}>
        <text>
          <span fg={colors.primary}>█ </span>
          <span fg={colors.textMuted}>Press </span>
          <span fg={colors.text}>[↑][↓]</span>
          <span fg={colors.textMuted}> to navigate </span>
          <span fg={colors.text}>[Enter]</span>
          <span fg={colors.textMuted}> for details </span>
          <span fg={colors.text}>[ESC]</span>
          <span fg={colors.textMuted}> to go back</span>
        </text>
      </box>
    </box>
  );
}
