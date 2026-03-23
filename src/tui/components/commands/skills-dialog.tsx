/**
 * Skills Dialog
 *
 * Dialog overlay displaying installed skills grouped by source, with token estimates.
 * Arrow keys to navigate, Enter for detail view, Escape to close.
 */

import { useState, useMemo, useEffect, useRef } from "react";
import { useKeyboard } from "@opentui/react";
import { ScrollBoxRenderable } from "@opentui/core";
import { scrollToIndex } from "../../utils/scroll";
import { useCommand } from "../../context/command";
import { useTheme } from "../../theme";
import { useToast } from "../../context/toast";
import { Dialog } from "../../context/dialog";
import DialogLayout from "../dialog-layout";
import { useMarkdownSyntaxStyle } from "../shared/markdown-viewer";
import { openFileInDefaultApp } from "../../utils/open-file";
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

export default function SkillsDialog({
  onClose,
  initialSlug,
}: SkillsDialogProps) {
  const { colors } = useTheme();
  const { skillsRegistry } = useCommand();
  const { toast } = useToast();

  const [selectedIndex, setSelectedIndex] = useState(0);
  const scrollboxRef = useRef<ScrollBoxRenderable | null>(null);
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
    // Detail view — intercept escape and [E]; let scrollbox handle scroll keys
    if (detailSkill) {
      if (evt.name === "escape") {
        evt.preventDefault();
        setDetailSkill(null);
      }
      if ((evt.name === "e" || evt.name === "E") && !evt.ctrl && !evt.meta) {
        evt.preventDefault();
        openFileInDefaultApp(detailSkill.filePath).then((err) => {
          if (err) toast(err, "error");
        });
      }
      return;
    }

    // List view — consume all keys
    evt.preventDefault();

    switch (evt.name) {
      case "escape":
        onClose();
        break;

      case "up":
      case "k":
        setSelectedIndex((prev) => (prev > 0 ? prev - 1 : flatList.length - 1));
        break;

      case "down":
      case "j":
        setSelectedIndex((prev) => (prev < flatList.length - 1 ? prev + 1 : 0));
        break;

      case "return":
        if (flatList[selectedIndex]) {
          setDetailSkill(flatList[selectedIndex]);
        }
        break;
    }
  });

  // Clamp index
  const safeIndex = Math.min(selectedIndex, flatList.length - 1);

  useEffect(() => {
    scrollToIndex(
      scrollboxRef.current,
      safeIndex,
      flatList,
      (skill) => skill.slug,
    );
  }, [safeIndex, flatList]);

  const syntaxStyle = useMarkdownSyntaxStyle();

  // ---------- Detail view ----------
  if (detailSkill) {
    const m = detailSkill.manifest;
    const instrText = detailInstructions ?? "";
    const instrTokens = estimateTokens(instrText);
    const descTokens = estimateTokens(m.description);

    const detailTitle = (
      <text>
        <span fg={colors.primary}>{detailSkill.slug}</span>
        {m.version && <span fg={colors.textMuted}> v{m.version}</span>}
        <span fg={colors.textMuted}>
          {" "}
          {detailInstructions !== null
            ? `~${instrTokens + descTokens} tokens`
            : "loading..."}
        </span>
      </text>
    );

    return (
      <Dialog size="large" onClose={() => setDetailSkill(null)}>
        <DialogLayout
          title={detailTitle}
          escLabel="back"
          footerActions={[
            { key: "E", label: "open in editor", variant: "primary" },
          ]}
        >
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

          {/* Scrollable markdown instructions */}
          <scrollbox
            style={{
              rootOptions: {
                flexGrow: 1,
                flexShrink: 1,
                width: "100%",
                overflow: "hidden",
              },
              contentOptions: {
                paddingLeft: 2,
                paddingRight: 2,
                paddingTop: 1,
                paddingBottom: 1,
                flexDirection: "column",
              },
              scrollbarOptions: {
                trackOptions: {
                  foregroundColor: colors.primary,
                  backgroundColor: colors.backgroundElement,
                },
              },
            }}
            stickyScroll={false}
            focused={true}
          >
            {detailInstructions !== null ? (
              <markdown
                content={instrText}
                syntaxStyle={syntaxStyle}
                conceal={true}
              />
            ) : (
              <text fg={colors.textMuted}>Loading instructions...</text>
            )}
          </scrollbox>
        </DialogLayout>
      </Dialog>
    );
  }

  // ---------- List view ----------

  return (
    <Dialog size="large" onClose={onClose}>
      <DialogLayout
        title="Skills"
        footerActions={[{ key: "Enter", label: "details", variant: "primary" }]}
      >
        {/* Skill list */}
        <scrollbox
          ref={scrollboxRef}
          style={{
            rootOptions: {
              flexShrink: 1,
              width: "100%",
              maxHeight: Math.max(flatList.length + groups.length, 1),
            },
            contentOptions: {
              flexDirection: "column",
            },
          }}
          stickyScroll={false}
          focused={true}
        >
          {groups.map((group) => (
            <box key={group.label} flexDirection="column">
              <text fg={colors.textMuted}>{group.label}</text>
              {group.skills.map((skill) => {
                const idx = flatList.indexOf(skill);
                const selected = idx === safeIndex;
                return (
                  <box key={skill.slug} id={skill.slug} flexDirection="row">
                    <text fg={selected ? colors.primary : colors.textMuted}>
                      {selected ? "❯ " : "  "}
                    </text>
                    <text fg={selected ? colors.primary : colors.text}>
                      {skill.slug}
                    </text>
                    <text fg={colors.textMuted}>
                      {" "}
                      · ~{estimateTokens(skill.manifest.description)} tokens
                    </text>
                  </box>
                );
              })}
            </box>
          ))}

          {allSkills.length === 0 && (
            <text fg={colors.textMuted}>No skills installed.</text>
          )}
        </scrollbox>
      </DialogLayout>
    </Dialog>
  );
}
