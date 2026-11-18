import { readFileSync } from "node:fs";
import ts from "typescript";
import { expect, it } from "vitest";

it.each([
  [true, "native", "external"],
  [false, "external", "external"],
  [false, "native", "native"],
  [false, undefined, undefined],
])("operator forwards its CLI finding policy (%s, %s)", (flag, configured, expected) => {
  const source = ts.createSourceFile(
    "cli.ts",
    readFileSync(new URL("../cli.ts", import.meta.url), "utf8"),
    ts.ScriptTarget.Latest,
    true,
  );
  const operator = source.statements.find(
    (node) =>
      ts.isFunctionDeclaration(node) && node.name?.text === "runOperator",
  );
  let argument: ts.ObjectLiteralExpression | undefined;
  function visit(node: ts.Node) {
    if (
      ts.isCallExpression(node) &&
      node.expression.getText(source) === "runOffensiveSecurityAgent"
    )
      argument = node.arguments[0] as ts.ObjectLiteralExpression;
    ts.forEachChild(node, visit);
  }
  expect(operator).toBeDefined();
  visit(operator!);
  const property = argument?.properties.find(
    (node) =>
      ts.isPropertyAssignment(node) &&
      node.name.getText(source) === "findingPolicy",
  ) as ts.PropertyAssignment | undefined;
  expect(property).toBeDefined();
  const value = new Function(
    "hasFlag",
    "pensarConfig",
    `return (${property!.initializer.getText(source)})`,
  )((name: string) => name === "--external-findings" && flag, {
    findingPolicy: configured,
  });
  expect(value).toBe(expected);
});
