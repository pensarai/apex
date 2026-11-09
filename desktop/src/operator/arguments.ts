import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { OPERATOR_MODE_CYCLE } from "../../../src/core/operator";
import { parseWebFlags } from "../../../src/tui/utils/command-flags";
import { splitCommand } from "../commands";
import type { OperatorLaunch, OperatorMode } from "./contract";

export function operatorArguments(
  command: string,
  cwd: string,
): OperatorLaunch {
  const [raw, ...args] = splitCommand(command);
  const name = raw?.toLowerCase();
  if (name === "/threat-model" || name === "/tm") {
    const { values } = parseArgs({
      args,
      options: {
        output: { type: "string", short: "o" },
        model: { type: "string" },
      },
    });
    return {
      skill: "threat-model",
      skillOutput: values.output,
      model: values.model,
      strikeMode: false,
      lanceMode: false,
    };
  }
  if (name === "/prompt-injection" || name === "/pi") {
    const { values } = parseArgs({
      args,
      options: { library: { type: "string" }, target: { type: "string" } },
    });
    return {
      skill: "prompt-injection",
      promptInjectionLibrarySource: values.library
        ? resolve(cwd, values.library)
        : undefined,
      target: values.target,
      strikeMode: false,
      lanceMode: false,
    };
  }
  if (name !== "/operator" && name !== "/o")
    throw new Error("Expected an operator command.");
  const { values } = parseArgs({
    args,
    options: {
      target: { type: "string", short: "t" },
      name: { type: "string", short: "n" },
      mode: { type: "string", short: "m" },
      autopilot: { type: "boolean" },
      "no-approval": { type: "boolean" },
      "require-approval": { type: "boolean" },
      sandbox: { type: "boolean" },
      "task-driven": { type: "boolean" },
      model: { type: "string" },
      hosts: { type: "string" },
      ports: { type: "string" },
      strict: { type: "boolean" },
      "auth-url": { type: "string" },
      "auth-user": { type: "string" },
      "auth-pass": { type: "string" },
      "auth-instructions": { type: "string" },
      headers: { type: "string" },
      header: { type: "string", multiple: true },
    },
  });
  if (values.mode && !OPERATOR_MODE_CYCLE.includes(values.mode as OperatorMode))
    throw new Error("Choose plan, manual or auto for --mode.");
  if (values.headers && !["none", "default", "custom"].includes(values.headers))
    throw new Error("Choose default, none or custom for --headers.");
  if (
    values.ports
      ?.split(",")
      .some(
        (p) => !/^\d+$/.test(p.trim()) || Number(p) < 1 || Number(p) > 65535,
      )
  )
    throw new Error("Allowed ports must be integers from 1 to 65535.");
  if (values["auth-pass"] && !values["auth-user"])
    throw new Error("Supply --auth-user with --auth-pass.");
  if (
    values.header?.length &&
    (values.headers === "none" || values.headers === "default")
  )
    throw new Error("Use --headers custom with --header.");
  const flags = parseWebFlags(args);
  return {
    target: flags.target,
    name: flags.name,
    mode: flags.mode ?? (flags.requireApproval === false ? "auto" : "manual"),
    sandbox: flags.sandbox,
    model: flags.model,
    taskDriven: flags.taskDriven,
    scopeConstraints: {
      allowedHosts: flags.hosts,
      allowedPorts: flags.ports,
      strictScope: flags.strict,
    },
    authCredentials: flags.authUser
      ? [
          {
            username: flags.authUser,
            password: flags.authPass,
            loginUrl: flags.authUrl,
          },
        ]
      : undefined,
    authenticationInstructions: flags.authInstructions,
    headers:
      flags.headersMode === "none"
        ? {}
        : flags.headersMode === "custom"
          ? (flags.customHeaders ?? {})
          : undefined,
  };
}
