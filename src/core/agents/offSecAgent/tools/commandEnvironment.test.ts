import { describe, expect, it } from "vitest";
import {
  curatedCommandEnv,
  mergeCommandEnv,
  windowsCommandShell,
} from "./commandEnvironment";

describe("command environment", () => {
  it("resolves cmd independently of PATH and environment-key casing", () => {
    expect(
      windowsCommandShell({
        cOmSpEc: "D:\\Windows\\System32\\cmd.exe",
        Path: "",
      }),
    ).toBe("D:\\Windows\\System32\\cmd.exe");
    expect(
      windowsCommandShell({ SystemRoot: "D:\\Windows", ComSpec: "cmd" }),
    ).toBe("D:\\Windows\\System32\\cmd.exe");
    expect(windowsCommandShell({ windir: "E:\\WINNT" })).toBe(
      "E:\\WINNT\\System32\\cmd.exe",
    );
    expect(windowsCommandShell({})).toBe("C:\\Windows\\System32\\cmd.exe");
  });

  it("retains Windows runtime essentials but not unrelated secrets", () => {
    const env = curatedCommandEnv(
      {
        Path: "C:\\Tools",
        SystemRoot: "C:\\Windows",
        PATHEXT: ".COM;.EXE;.BAT;.CMD",
        TEMP: "C:\\Temp",
        USERPROFILE: "C:\\Users\\Ada",
        APPDATA: "C:\\Users\\Ada\\AppData\\Roaming",
        APEX_TEST_INFRA_SECRET: "must-not-leak",
      },
      true,
    );
    expect(env).toMatchObject({
      PATH: "C:\\Tools",
      SYSTEMROOT: "C:\\Windows",
      PATHEXT: ".COM;.EXE;.BAT;.CMD",
      TEMP: "C:\\Temp",
      USERPROFILE: "C:\\Users\\Ada",
      APPDATA: "C:\\Users\\Ada\\AppData\\Roaming",
      COMSPEC: "C:\\Windows\\System32\\cmd.exe",
    });
    expect(env).not.toHaveProperty("APEX_TEST_INFRA_SECRET");
  });

  it("merges Windows overrides without duplicate case-insensitive names", () => {
    expect(
      mergeCommandEnv(
        true,
        { Path: "workspace", temp: "one" },
        { PATH: "host" },
        { path: "invocation", TEMP: "two" },
      ),
    ).toEqual({ PATH: "invocation", TEMP: "two" });
  });

  it("preserves the POSIX allowlist and case-sensitive merge", () => {
    const env = curatedCommandEnv(
      {
        PATH: "/bin",
        HOME: "/home/test",
        USER: "test",
        LANG: "C",
        TMPDIR: "/tmp",
        ComSpec: "ignored",
        SECRET: "hidden",
      },
      false,
    );
    expect(env).toEqual({
      PATH: "/bin",
      HOME: "/home/test",
      USER: "test",
      LANG: "C",
      TMPDIR: "/tmp",
    });
    expect(
      mergeCommandEnv(
        false,
        { PATH: "first", Path: "distinct" },
        { PATH: "last" },
      ),
    ).toEqual({ PATH: "last", Path: "distinct" });
  });
});
