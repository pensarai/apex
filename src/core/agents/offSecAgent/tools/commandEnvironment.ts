import { win32 } from "node:path";

/** Windows environment names are case-insensitive, even in plain JS objects. */
function readWindowsEnv(
  env: NodeJS.ProcessEnv,
  name: string,
): string | undefined {
  return Object.entries(env).find(
    ([key]) => key.toUpperCase() === name.toUpperCase(),
  )?.[1];
}

/** Resolve the host's shell independently of an agent-supplied PATH. */
export function windowsCommandShell(env: NodeJS.ProcessEnv): string {
  const comspec = readWindowsEnv(env, "COMSPEC");
  if (comspec && win32.isAbsolute(comspec)) return comspec;
  const root =
    readWindowsEnv(env, "SYSTEMROOT") ||
    readWindowsEnv(env, "WINDIR") ||
    "C:\\Windows";
  return win32.join(root, "System32", "cmd.exe");
}

/** Keep native runtime essentials without leaking arbitrary host credentials. */
export function curatedCommandEnv(
  env: NodeJS.ProcessEnv,
  windows: boolean,
): NodeJS.ProcessEnv {
  const read = (key: string) => (windows ? readWindowsEnv(env, key) : env[key]);
  const out: NodeJS.ProcessEnv = {
    PATH: read("PATH") ?? "",
    HOME: read("HOME") ?? "",
    USER: read("USER") ?? "",
    LANG: read("LANG"),
    TMPDIR: read("TMPDIR"),
  };
  if (windows) {
    for (const key of [
      "SYSTEMROOT",
      "WINDIR",
      "SYSTEMDRIVE",
      "PATHEXT",
      "TEMP",
      "TMP",
      "USERPROFILE",
      "HOMEDRIVE",
      "HOMEPATH",
      "APPDATA",
      "LOCALAPPDATA",
      "PROGRAMDATA",
      "PROGRAMFILES",
      "PROGRAMFILES(X86)",
      "COMMONPROGRAMFILES",
      "COMMONPROGRAMFILES(X86)",
      "USERNAME",
      "USERDOMAIN",
    ]) {
      const value = read(key);
      if (value !== undefined) out[key] = value;
    }
    out.COMSPEC = windowsCommandShell(env);
  }
  return out;
}

/** Last source wins; Windows must not receive conflicting Path/PATH keys. */
export function mergeCommandEnv(
  windows: boolean,
  ...sources: (NodeJS.ProcessEnv | undefined)[]
): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const source of sources) {
    for (const [key, value] of Object.entries(source ?? {})) {
      out[windows ? key.toUpperCase() : key] = value;
    }
  }
  return out;
}
