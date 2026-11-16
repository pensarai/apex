import { Markdown } from "@pensarai/design-system/ui/markdown";
import { type ComponentProps, memo } from "react";

export const LocalMarkdown = memo(function LocalMarkdown({
  text,
  options,
}: {
  text: string;
  options?: ComponentProps<typeof Markdown>["options"];
}) {
  return (
    <Markdown
      options={options}
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
