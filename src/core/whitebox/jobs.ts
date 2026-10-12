import { createRequire } from "node:module";
import type { SessionInfo } from "../session";
import { createWhiteboxJobKernel } from "./jobKernel";
import type { WhiteboxJobRecord } from "./types";

const kernel = createWhiteboxJobKernel(createRequire(import.meta.url));

export function startWhiteboxJob(input: {
  session: SessionInfo;
  command: string;
  cwd: string;
  timeoutSeconds: number;
  name?: string;
  env?: Record<string, string>;
}): WhiteboxJobRecord {
  return kernel.startWhiteboxJob(input);
}

export const pollWhiteboxJob = kernel.pollWhiteboxJob;
export const stopWhiteboxJob = kernel.stopWhiteboxJob;
export const readWhiteboxJobLog = kernel.readWhiteboxJobLog;
