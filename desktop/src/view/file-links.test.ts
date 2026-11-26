import { describe, expect, it } from "vitest";
import { fileReference } from "../file-reference";
import { streamFadePlugin } from "../operator/stream-fade";
import { fileLinksPlugin } from "./file-links";

describe("local file references", () => {
  it.each([
    ["/Users/test/report.csv", "/Users/test/report.csv", "report.csv"],
    ["./reports/findings.md", "./reports/findings.md", "findings.md"],
    [
      "~/Reports/Final assessment.md",
      "~/Reports/Final assessment.md",
      "Final assessment.md",
    ],
    [
      "file:///tmp/Final%20report.md",
      "/tmp/Final report.md",
      "Final report.md",
    ],
    ["/tmp/app.ts:12:4", "/tmp/app.ts", "app.ts"],
    ["src/app.ts#L12-L20", "src/app.ts", "app.ts"],
    ["C:\\Reports\\results.csv", "C:\\Reports\\results.csv", "results.csv"],
  ])("recognizes %s", (input, path, name) => {
    expect(fileReference(input)).toEqual({ path, name });
  });

  it.each([
    "https://example.test/report.csv",
    "javascript:alert(1)",
    "file://remote/report.csv",
    "//example.test/report.csv",
    "#section.md",
    "/api/users",
    "/tmp/bad\0.csv",
  ])("leaves non-file references alone: %s", (input) => {
    expect(fileReference(input)).toBeUndefined();
  });

  it("decodes link destinations once, preserving literal percent sequences in file paths", () => {
    expect(fileReference("/tmp/report%2520.csv", true)?.path).toBe(
      "/tmp/report%20.csv",
    );
    expect(fileReference("/tmp/report%20.csv")?.path).toBe(
      "/tmp/report%20.csv",
    );
  });
});

type Node = Parameters<ReturnType<typeof fileLinksPlugin>>[0];
const text = (value: string): Node => ({ type: "text", value });
const element = (tagName: string, children: Node[], properties = {}): Node => ({
  type: "element",
  tagName,
  children,
  properties,
});
const transform = (children: Node[]) => {
  const tree: Node = { type: "root", children };
  fileLinksPlugin()(tree);
  return tree.children ?? [];
};

describe("message file links", () => {
  it("replaces Markdown destinations and inline paths with just the filename", () => {
    const nodes = transform([
      element("a", [text("Final working CSV")], { href: "/tmp/final.csv" }),
      element("code", [text("/tmp/final.csv")]),
    ]);
    for (const node of nodes) {
      expect(node.properties).toEqual({
        href: "#",
        "data-file-path": "/tmp/final.csv",
      });
      expect(node.children).toEqual([text("final.csv")]);
    }
  });

  it("recognizes plain and quoted paths without swallowing punctuation or nearby URLs", () => {
    const nodes = transform([
      text(
        'Files: (/tmp/final.csv), "/tmp/Report final.md". https://example.test/final.csv',
      ),
    ]);
    expect(
      nodes.map((node) => node.properties?.["data-file-path"] ?? node.value),
    ).toEqual([
      "Files: (",
      "/tmp/final.csv",
      "), ",
      "/tmp/Report final.md",
      ". https://example.test/final.csv",
    ]);
  });

  it("preserves fenced code, inline shell commands, web links and route paths", () => {
    const nodes = [
      element("pre", [element("code", [text("/tmp/final.csv")])]),
      element("code", [text("cat /tmp/final.csv")]),
      element("a", [text("Report")], {
        href: "https://example.test/final.csv",
      }),
      text("GET /api/users"),
    ];
    expect(transform(structuredClone(nodes))).toEqual(nodes);
  });

  it("keeps streaming offsets on surrounding prose and file labels atomic", () => {
    const value = "Read /tmp/final.csv now";
    const tree: Node = {
      type: "root",
      children: [
        {
          ...text(value),
          position: { start: { offset: 0 }, end: { offset: value.length } },
        },
      ],
    };
    fileLinksPlugin()(tree);
    streamFadePlugin([{ start: 20, end: value.length, time: 100 }], 120)()(
      tree,
    );
    expect(tree.children?.[1].children).toEqual([text("final.csv")]);
    expect(tree.children?.at(-1)).toMatchObject({
      tagName: "span",
      children: [text("now")],
    });
  });
});
