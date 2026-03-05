import { useState } from "react";
import { useKeyboard } from "@opentui/react";
import Input from "../input";
import { useRoute } from "../../context/route";
import { useTheme } from "../../theme";
import { saveSkill, slugify, skillExists } from "../../../core/skills";
import type { Skill } from "../../../core/skills";

type WizardStep = "name" | "description" | "content" | "confirm" | "saving";

export default function CreateSkillWizard() {
  const { colors } = useTheme();
  const route = useRoute();

  const [step, setStep] = useState<WizardStep>("name");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [content, setContent] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [confirmFocused, setConfirmFocused] = useState(0);

  const slug = slugify(name);

  async function handleSave() {
    if (!name.trim() || !content.trim()) return;

    setStep("saving");
    setError(null);

    try {
      if (await skillExists(slug)) {
        setError(`A skill with the slug "${slug}" already exists.`);
        setStep("confirm");
        return;
      }

      const skill: Skill = {
        name: name.trim(),
        description: description.trim(),
        content: content.trim(),
      };

      await saveSkill(skill);
      route.navigate({ type: "base", path: "home" });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save skill");
      setStep("confirm");
    }
  }

  useKeyboard((key) => {
    if (key.name === "escape") {
      if (step === "saving") return;
      if (step === "confirm") {
        setStep("content");
        return;
      }
      if (step === "content") {
        setStep("description");
        return;
      }
      if (step === "description") {
        setStep("name");
        return;
      }
      route.navigate({ type: "base", path: "home" });
      return;
    }

    if (step === "name") {
      if (key.name === "return" && name.trim()) {
        setStep("description");
      }
      return;
    }

    if (step === "description") {
      if (key.name === "return") {
        setStep("content");
      }
      return;
    }

    if (step === "content") {
      if (key.name === "return" && !key.shift && content.trim()) {
        setStep("confirm");
      }
      return;
    }

    if (step === "confirm") {
      if (key.name === "up" || (key.name === "tab" && key.shift)) {
        setConfirmFocused((p) => Math.max(0, p - 1));
        return;
      }
      if (key.name === "down" || key.name === "tab") {
        setConfirmFocused((p) => Math.min(1, p + 1));
        return;
      }
      if (key.name === "return") {
        if (confirmFocused === 0) {
          handleSave();
        } else {
          route.navigate({ type: "base", path: "home" });
        }
      }
    }
  });

  if (step === "saving") {
    return (
      <box
        flexDirection="column"
        width="100%"
        height="100%"
        alignItems="center"
        justifyContent="center"
      >
        <text fg={colors.primary}>Saving skill...</text>
      </box>
    );
  }

  if (step === "name") {
    return (
      <box width="100%" flexDirection="column" gap={2} paddingLeft={4}>
        <text fg={colors.text}>Create Skill</text>
        <text fg={colors.textMuted}>
          Skills are reusable prompts / workflows available via / commands
        </text>

        {error && <text fg={colors.error}>Error: {error}</text>}

        <Input
          label="Skill Name"
          description='A short name (e.g. "SQL Injection Test")'
          placeholder="My Custom Skill"
          value={name}
          onInput={setName}
          focused={true}
        />

        {name.trim() && (
          <text fg={colors.textMuted}>Slash command: /{slug}</text>
        )}

        <box flexDirection="column" gap={0} marginTop={1}>
          <text>
            <span fg={colors.primary}>█ </span>
            <span fg={colors.textMuted}>Press </span>
            <span fg={colors.text}>[Enter]</span>
            <span fg={colors.textMuted}> to continue</span>
          </text>
          <text>
            <span fg={colors.primary}>█ </span>
            <span fg={colors.textMuted}>Press </span>
            <span fg={colors.text}>[ESC]</span>
            <span fg={colors.textMuted}> to cancel</span>
          </text>
        </box>
      </box>
    );
  }

  if (step === "description") {
    return (
      <box width="100%" flexDirection="column" gap={2} paddingLeft={4}>
        <text fg={colors.text}>Create Skill — Description</text>
        <text fg={colors.textMuted}>
          Skill: {name} (/{slug})
        </text>

        <Input
          label="Description"
          description="One-line description shown in autocomplete (optional)"
          placeholder="Test for SQL injection vulnerabilities"
          value={description}
          onInput={setDescription}
          focused={true}
        />

        <box flexDirection="column" gap={0} marginTop={1}>
          <text>
            <span fg={colors.primary}>█ </span>
            <span fg={colors.textMuted}>Press </span>
            <span fg={colors.text}>[Enter]</span>
            <span fg={colors.textMuted}> to continue</span>
          </text>
          <text>
            <span fg={colors.primary}>█ </span>
            <span fg={colors.textMuted}>Press </span>
            <span fg={colors.text}>[ESC]</span>
            <span fg={colors.textMuted}> to go back</span>
          </text>
        </box>
      </box>
    );
  }

  if (step === "content") {
    return (
      <box width="100%" flexDirection="column" gap={2} paddingLeft={4}>
        <text fg={colors.text}>Create Skill — Prompt Content</text>
        <text fg={colors.textMuted}>
          Skill: {name} (/{slug})
        </text>

        <Input
          label="Prompt Content"
          description="The directive / prompt that will be sent to the agent"
          placeholder="Test the target for SQL injection vulnerabilities..."
          value={content}
          onInput={setContent}
          focused={true}
        />

        <box flexDirection="column" gap={0} marginTop={1}>
          <text>
            <span fg={colors.primary}>█ </span>
            <span fg={colors.textMuted}>Press </span>
            <span fg={colors.text}>[Enter]</span>
            <span fg={colors.textMuted}> to review</span>
          </text>
          <text>
            <span fg={colors.primary}>█ </span>
            <span fg={colors.textMuted}>Press </span>
            <span fg={colors.text}>[ESC]</span>
            <span fg={colors.textMuted}> to go back</span>
          </text>
        </box>
      </box>
    );
  }

  // Confirm step
  return (
    <box width="100%" flexDirection="column" gap={1} paddingLeft={4}>
      <text fg={colors.text}>Create Skill — Review</text>

      {error && <text fg={colors.error}>Error: {error}</text>}

      <box flexDirection="column" marginTop={1} gap={1}>
        <box flexDirection="row" gap={1}>
          <text fg={colors.textMuted}>Name:</text>
          <text fg={colors.text}>{name}</text>
        </box>
        <box flexDirection="row" gap={1}>
          <text fg={colors.textMuted}>Command:</text>
          <text fg={colors.primary}>/{slug}</text>
        </box>
        {description && (
          <box flexDirection="row" gap={1}>
            <text fg={colors.textMuted}>Description:</text>
            <text fg={colors.text}>{description}</text>
          </box>
        )}
        <box flexDirection="column" marginTop={1}>
          <text fg={colors.textMuted}>Prompt:</text>
          <box paddingLeft={2} marginTop={0}>
            <text fg={colors.text}>{content}</text>
          </box>
        </box>
      </box>

      <box flexDirection="column" marginTop={2} gap={0}>
        {/* Save button */}
        <box flexDirection="row" gap={1}>
          <text fg={confirmFocused === 0 ? colors.primary : colors.textMuted}>
            {confirmFocused === 0 ? "▸" : " "}
          </text>
          <text fg={confirmFocused === 0 ? colors.primary : colors.textMuted}>
            {confirmFocused === 0 ? "[" : " "}Save Skill
            {confirmFocused === 0 ? "]" : " "}
          </text>
        </box>

        {/* Cancel button */}
        <box flexDirection="row" gap={1}>
          <text fg={confirmFocused === 1 ? colors.primary : colors.textMuted}>
            {confirmFocused === 1 ? "▸" : " "}
          </text>
          <text fg={confirmFocused === 1 ? colors.textMuted : colors.textMuted}>
            {confirmFocused === 1 ? "[" : " "}Cancel
            {confirmFocused === 1 ? "]" : " "}
          </text>
        </box>
      </box>

      <box flexDirection="column" gap={0} marginTop={2}>
        <text fg={colors.textMuted}>
          ↑/↓ navigate | Enter select | ESC back
        </text>
        <text fg={colors.textMuted}>Saved to ~/.pensar/skills/{slug}.md</text>
      </box>
    </box>
  );
}
