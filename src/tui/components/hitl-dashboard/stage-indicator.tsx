import { RGBA } from "@opentui/core";
import type { HITLStage } from "../../../core/hitl";
import { getStagesInOrder } from "../../../core/hitl";

const greenBullet = RGBA.fromInts(76, 175, 80, 255);
const creamText = RGBA.fromInts(255, 248, 220, 255);
const dimText = RGBA.fromInts(120, 120, 120, 255);

interface StageIndicatorProps {
  currentStage: HITLStage;
  compact?: boolean;
}

export default function StageIndicator({ currentStage, compact = false }: StageIndicatorProps) {
  const stages = getStagesInOrder();
  const currentIndex = stages.findIndex((s) => s.stage === currentStage);
  const progressPercent = Math.round(((currentIndex + 1) / stages.length) * 100);

  if (compact) {
    return (
      <box flexDirection="row" gap={1} alignItems="center">
        <text fg={creamText}>{stages[currentIndex]?.name || currentStage}</text>
        <text fg={dimText}>({currentIndex + 1}/{stages.length})</text>
      </box>
    );
  }

  return (
    <box flexDirection="column" gap={0}>
      <box flexDirection="row" gap={1}>
        {stages.map((stage, idx) => {
          const isCompleted = idx < currentIndex;
          const isCurrent = idx === currentIndex;
          const fg = isCompleted ? greenBullet : isCurrent ? creamText : dimText;
          const symbol = isCompleted ? "✓" : isCurrent ? "●" : "○";
          return (
            <text key={stage.stage} fg={fg}>
              {symbol} {stage.name}
            </text>
          );
        })}
      </box>
      <text fg={dimText}>[S] Change stage | Progress: {progressPercent}%</text>
    </box>
  );
}
