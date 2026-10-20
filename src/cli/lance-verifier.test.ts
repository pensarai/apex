import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";

it("round trips milestone and completion verdicts with the real Bun CLI transport", async () => {
  const module = fileURLToPath(new URL("./lance-verifier.ts", import.meta.url));
  const child = spawn(
    "bun",
    [
      "--no-env-file",
      "-e",
      `
    import { createIpcObjectiveVerifier } from ${JSON.stringify(module)};
    const channel = createIpcObjectiveVerifier();
    try {
      const milestone = await channel.verifyObjective({evidence:"milestone"}, new AbortController().signal);
      const complete = await channel.verifyObjective({evidence:"complete"}, new AbortController().signal);
      console.log(JSON.stringify({milestone,complete}));
    } finally { channel.close(); }
  `,
    ],
    { stdio: ["ignore", "pipe", "pipe", "ipc"], serialization: "json" },
  );
  const evidence: string[] = [];
  let output = "";
  child.stdout!.on("data", (bytes) => {
    output += bytes;
  });
  child.stderr!.on("data", (bytes) => {
    output += bytes;
  });
  child.on("message", (message) => {
    const input = message as { id: number; evidence: string };
    evidence.push(input.evidence);
    child.send({
      id: input.id,
      verified: true,
      objectiveComplete: input.evidence === "complete",
      verifierId: "fixture",
    });
  });
  const timer = setTimeout(() => child.kill("SIGKILL"), 5000);
  try {
    const code = await new Promise<number | null>((resolve, reject) => {
      child.on("close", resolve);
      child.on("error", reject);
    });
    expect(code, output).toBe(0);
    expect(evidence).toEqual(["milestone", "complete"]);
    expect(JSON.parse(output)).toMatchObject({
      milestone: { verified: true, objectiveComplete: false },
      complete: { verified: true, objectiveComplete: true },
    });
  } finally {
    clearTimeout(timer);
  }
});
