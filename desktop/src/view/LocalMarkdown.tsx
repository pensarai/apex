import { Markdown } from "@pensarai/design-system/ui/markdown";
import { memo } from "react";

export const LocalMarkdown = memo(function LocalMarkdown({
  text,
}: {
  text: string;
}) {
  return (
    <Markdown
      components={{
        img: ({ alt }) => <span>{alt}</span>,
        a: ({ children, href }) => (
          <span title={href}>
            {children}
            {href && <small> ({href})</small>}
          </span>
        ),
      }}
    >
      {text}
    </Markdown>
  );
});
