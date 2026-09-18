#!/usr/bin/env bun

import { readFile } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { z } from "zod";
import { exportTrajectoryBundle } from "../core/api/trajectoryExport";
import { markCommandFailed } from "./command-exit";

const requestSchema = z.strictObject({
  version: z.literal(1),
  sources: z
    .array(
      z.strictObject({
        id: z.string().min(1),
        path: z.string().min(1),
        sha256: z.string().regex(/^[a-f0-9]{64}$/),
        sizeBytes: z.number().int().nonnegative(),
      }),
    )
    .min(1),
  rootSourceId: z.string().min(1),
  agent: z.strictObject({
    name: z.string().min(1),
    version: z.string().min(1),
  }),
  exporter: z.strictObject({
    name: z.string().min(1),
    version: z.string().min(1),
  }),
  independentValidation: z
    .strictObject({
      status: z.enum(["passed", "failed"]),
      detail: z.string().min(1),
    })
    .optional(),
});

function showHelp(): void {
  console.log(`pensar export-trajectory — Convert saved Apex evidence to ATIF

Usage:
  pensar export-trajectory --input <request.json> --output <directory>

Options:
  --input <path>   Version 1 export request with saved evidence paths and digests
  --output <path>  Fresh output directory; existing paths are never overwritten
  -h, --help       Show this help message

The command reads recorded evidence only. A successful output contains
manifest.json as its commit marker. An optional independentValidation field
records a caller-supplied result; this command does not run an external
validator.`);
}

function options(
  argv: string[],
): { help: true } | { help: false; input: string; output: string } {
  if (argv.length === 1 && ["-h", "--help", "help"].includes(argv[0] ?? ""))
    return { help: true };
  const values = new Map<string, string>();
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!flag || !["--input", "--output"].includes(flag) || !value)
      throw new Error("expected --input <request.json> --output <directory>");
    if (values.has(flag)) throw new Error(`${flag} may be supplied only once`);
    values.set(flag, value);
  }
  const input = values.get("--input");
  const output = values.get("--output");
  if (!input || !output)
    throw new Error("--input and --output are both required");
  return { help: false, input, output };
}

export async function runExportTrajectoryCommand(
  argv: string[],
): Promise<void> {
  try {
    const parsedOptions = options(argv);
    if (parsedOptions.help) {
      showHelp();
      return;
    }
    const requestPath = resolve(parsedOptions.input);
    const request = requestSchema.parse(
      JSON.parse(await readFile(requestPath, "utf8")),
    );
    const requestDirectory = dirname(requestPath);
    const result = await exportTrajectoryBundle({
      ...request,
      sources: request.sources.map((source) => ({
        ...source,
        path: isAbsolute(source.path)
          ? source.path
          : resolve(requestDirectory, source.path),
      })),
      outputDirectory: parsedOptions.output,
    });
    console.log(
      JSON.stringify({
        outputDirectory: result.outputDirectory,
        manifestPath: result.manifestPath,
        rootTrajectoryId: result.manifest.rootTrajectoryId,
        fileCount: result.files.length,
      }),
    );
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    const code =
      error && typeof error === "object" && "code" in error
        ? `${String(error.code)}: `
        : "";
    console.error(`Error: ${code}${detail}`);
    markCommandFailed();
  }
}

await runExportTrajectoryCommand(process.argv.slice(2));
