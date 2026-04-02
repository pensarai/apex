/**
 * Plan Review Message
 *
 * Renders the pentest plan in a bordered box with approval hints.
 * Displayed when the agent calls submit_plan or the operator cycles
 * out of plan mode with an unapproved plan.
 */

import { useTheme } from "../../theme";
import {
  useMarkdownSyntaxStyle,
  useMarkdownRenderNode,
} from "../shared/markdown-viewer";

interface PlanReviewMessageProps {
  planContent: string;
}

export function PlanReviewMessage({ planContent }: PlanReviewMessageProps) {
  const { colors } = useTheme();
  const syntaxStyle = useMarkdownSyntaxStyle();
  const renderNode = useMarkdownRenderNode();

  return (
    <box flexDirection="column" marginTop={1} marginLeft={1} marginRight={1}>
      {/* Plan content in a bordered box */}
      <box
        flexDirection="column"
        border={true}
        borderColor={colors.secondary}
        paddingLeft={1}
        paddingRight={1}
        paddingTop={1}
        paddingBottom={1}
      >
        <markdown
          content={planContent}
          syntaxStyle={syntaxStyle}
          conceal={true}
          renderNode={renderNode}
        />
      </box>

      {/* Hints */}
      <box flexDirection="row" marginTop={1} marginLeft={1}>
        <text fg={colors.text}>
          Y approve · N reject · or type feedback to refine
        </text>
      </box>
    </box>
  );
}
