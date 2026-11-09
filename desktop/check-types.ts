import { resolve, sep } from "node:path";
import ts from "typescript";

const vendorSource = resolve("node_modules/electrobun") + sep;
for (const project of ["tsconfig.json", "tsconfig.host.json"]) {
  const config = ts.readConfigFile(project, ts.sys.readFile);
  const parsed = ts.parseJsonConfigFileContent(
    config.config,
    ts.sys,
    process.cwd(),
  );
  const program = ts.createProgram(parsed.fileNames, parsed.options);
  const errors = [
    ...(config.error ? [config.error] : []),
    ...parsed.errors,
    ...ts
      .getPreEmitDiagnostics(program)
      .filter((d) => !d.file?.fileName.startsWith(vendorSource)),
  ];
  if (errors.length) {
    console.error(
      ts.formatDiagnosticsWithColorAndContext(errors, {
        getCurrentDirectory: process.cwd,
        getNewLine: () => "\n",
        getCanonicalFileName: (name) => name,
      }),
    );
    process.exitCode = 1;
  }
}
