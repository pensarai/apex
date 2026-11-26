import { fileReference } from "../file-reference";

type Node = {
  type: string;
  tagName?: string;
  value?: string;
  children?: Node[];
  properties?: Record<string, unknown>;
  position?: { start: { offset?: number }; end: { offset?: number } };
};

function fileLink(file: { path: string; name: string }): Node {
  return {
    type: "element",
    tagName: "a",
    properties: { href: "#", "data-file-path": file.path },
    children: [{ type: "text", value: file.name }],
  };
}

export function fileLinksPlugin() {
  return (tree: Node) => {
    const visit = (parent: Node) => {
      if (!parent.children || parent.tagName === "pre") return;
      parent.children = parent.children.flatMap((node) => {
        if (node.tagName === "a") {
          const file = fileReference(String(node.properties?.href ?? ""), true);
          return [file ? fileLink(file) : node];
        }
        if (node.tagName === "code") {
          const text =
            node.children?.map((child) => child.value ?? "").join("") ?? "";
          const file =
            /\s/.test(text) && !/^(?:\/|~\/|\.{1,2}\/|[a-z]:[\\/])/i.test(text)
              ? undefined
              : fileReference(text);
          return [file ? fileLink(file) : node];
        }
        if (node.type !== "text" || !node.value) {
          visit(node);
          return [node];
        }
        const parts: Node[] = [];
        const text = node.value;
        let cursor = 0;
        const pattern =
          /(^|[\s([{"'])(?:"((?:\/|~\/|\.{1,2}\/|[a-z]:[\\/])[^"\n]+)"|'((?:\/|~\/|\.{1,2}\/|[a-z]:[\\/])[^'\n]+)'|((?:\/|~\/|\.{1,2}\/|[a-z]:[\\/])[^\s<>"'`]+))/gi;
        const slice = (start: number, end: number): Node => {
          const offset = node.position?.start.offset;
          return {
            type: "text",
            value: text.slice(start, end),
            ...(offset !== undefined &&
            node.position?.end.offset === offset + text.length
              ? {
                  position: {
                    start: { offset: offset + start },
                    end: { offset: offset + end },
                  },
                }
              : {}),
          };
        };
        for (const match of text.matchAll(pattern)) {
          const quoted = match[2] ?? match[3];
          const candidate = quoted ?? match[4].replace(/[.,;!?)\]}]+$/, "");
          const file = fileReference(candidate);
          if (!file) continue;
          const start = match.index + match[1].length;
          const end = start + (quoted ? quoted.length + 2 : candidate.length);
          if (start > cursor) parts.push(slice(cursor, start));
          parts.push(fileLink(file));
          cursor = end;
        }
        if (!cursor) return [node];
        if (cursor < text.length) parts.push(slice(cursor, text.length));
        return parts;
      });
    };
    visit(tree);
  };
}
