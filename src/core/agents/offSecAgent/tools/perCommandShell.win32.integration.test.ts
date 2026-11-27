import { describe, expect, it } from "vitest";
import { PerCommandShell } from "./perCommandShell";

describe.skipIf(process.platform !== "win32")(
  "PerCommandShell real Windows processes",
  () => {
    it("starts cmd with an empty PATH and preserves quoted executable paths", async () => {
      const shell = new PerCommandShell({ env: { PATH: "" } });
      try {
        const builtin = await shell.execute("echo apex-cmd-ready", {
          timeoutSeconds: 10,
        });
        expect(builtin.exitCode).toBe(0);
        expect(builtin.stdout.trim()).toBe("apex-cmd-ready");
        const quoted = await shell.execute(`"${process.execPath}" -p "6*7"`, {
          timeoutSeconds: 10,
        });
        expect(quoted.exitCode).toBe(0);
        expect(quoted.stdout.trim()).toBe("42");
      } finally {
        await shell.dispose();
      }
    });

    it("preserves native argv and supplies Windows runtime essentials", async () => {
      const shell = new PerCommandShell();
      const argument = String.raw`C:\Users\Ada O'Neil\My POCs\proof & %PATH% !.js`;
      try {
        const result = await shell.executeArgv(
          process.execPath,
          [
            "-e",
            "console.log(JSON.stringify({args:process.argv.slice(1),root:process.env.SystemRoot,comspec:process.env.ComSpec,extensions:process.env.PATHEXT}))",
            argument,
          ],
          { timeoutSeconds: 10 },
        );
        expect(result.exitCode).toBe(0);
        const output = JSON.parse(result.stdout);
        expect(output.args).toEqual([argument]);
        expect(output.root).toBeTruthy();
        expect(output.comspec).toMatch(/cmd\.exe$/i);
        expect(output.extensions).toMatch(/\.EXE/i);
      } finally {
        await shell.dispose();
      }
    });
  },
);
