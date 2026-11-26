import { Markdown } from "@pensarai/design-system/ui/markdown";
import { File } from "lucide-react";
import { type ComponentProps, memo, useContext, useState } from "react";
import { isBrowserFile } from "../browser/contract";
import { BrowserLinkContext } from "../browser/links";
import { fileReference } from "../file-reference";
import { api } from "./bridge";
import { fileLinksPlugin } from "./file-links";

function FileLink({ path, sessionId }: { path: string; sessionId?: string }) {
  const [error, setError] = useState("");
  const openBrowser = useContext(BrowserLinkContext);
  const file = fileReference(path);
  if (!file) return <span>{path}</span>;
  return (
    <>
      <button
        type="button"
        className="inline-flex max-w-full items-baseline gap-1 align-baseline font-mono text-accent hover:underline underline-offset-4"
        title={path}
        aria-label={`Open ${file.name}`}
        onClick={() => {
          setError("");
          const open =
            openBrowser && isBrowserFile(file.path)
              ? openBrowser({ type: "open-file", path: file.path, sessionId })
              : api.openLocalFile({ path, sessionId });
          void open.catch((e) => setError(String(e)));
        }}
      >
        <File size={13} className="self-center shrink-0" aria-hidden="true" />
        <span className="break-all">{file.name}</span>
      </button>
      {error && (
        <span className="ml-2 text-fg-3" role="alert">
          {error}
        </span>
      )}
    </>
  );
}

function WebLink({
  href,
  children,
}: {
  href: string;
  children: React.ReactNode;
}) {
  const openBrowser = useContext(BrowserLinkContext);
  const [error, setError] = useState("");
  if (!openBrowser || !/^https?:\/\//i.test(href))
    return (
      <span title={href}>
        {children}
        <small> ({href})</small>
      </span>
    );
  return (
    <>
      <a
        href={href}
        title={href}
        className="text-accent hover:underline underline-offset-4"
        onClick={(event) => {
          event.preventDefault();
          setError("");
          void openBrowser({ type: "navigate", url: href }).catch((cause) =>
            setError(String(cause)),
          );
        }}
      >
        {children}
      </a>
      {error && (
        <span className="ml-2 text-fg-3" role="alert">
          {error}
        </span>
      )}
    </>
  );
}

export const LocalMarkdown = memo(function LocalMarkdown({
  text,
  options,
  sessionId,
}: {
  text: string;
  options?: ComponentProps<typeof Markdown>["options"];
  sessionId?: string;
}) {
  return (
    <Markdown
      options={{
        ...options,
        rehypePlugins: [fileLinksPlugin, ...(options?.rehypePlugins ?? [])],
      }}
      components={{
        img: ({ alt }) => <span>{alt}</span>,
        a: ({ children, href, node }) =>
          typeof node?.properties["data-file-path"] === "string" ? (
            <FileLink
              path={node.properties["data-file-path"]}
              sessionId={sessionId}
            />
          ) : href ? (
            <WebLink href={href}>{children}</WebLink>
          ) : (
            <span>{children}</span>
          ),
      }}
    >
      {text}
    </Markdown>
  );
});
