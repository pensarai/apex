import { join } from "node:path";

const childScript = join(import.meta.dirname, "localWorkerChild.ts");
const databasePath = process.env.APEX_WORKER_DB!;
const runId = process.env.APEX_WORKER_RUN_ID!;

const { launchLocalWorker } = await import("../launchLocalWorker");

await launchLocalWorker({
  runId,
  databasePath,
  executable: { command: "bun", args: [childScript] },
});

console.log("LAUNCHED");
