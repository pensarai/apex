import { randomBytes } from "crypto";
import z from "zod";

const prefixes = {
  session: "ses",
  message: "msg",
  permission: "per",
  user: "usr",
  part: "prt",
  node: "nod",
  event: "evt",
} as const;

export type IdentifierPrefix = keyof typeof prefixes;

export function schema(prefix: IdentifierPrefix) {
  return z.string().startsWith(prefixes[prefix]);
}

const LENGTH = 26;

let lastTimestamp = 0;
let counter = 0;

export function ascending(prefix: IdentifierPrefix, given?: string) {
  return generateID(prefix, false, given);
}

export function descending(prefix: IdentifierPrefix, given?: string) {
  return generateID(prefix, true, given);
}

function generateID(
  prefix: IdentifierPrefix,
  descending: boolean,
  given?: string,
): string {
  if (!given) {
    return create(prefix, descending);
  }

  if (!given.startsWith(prefixes[prefix])) {
    throw new Error(`ID ${given} does not start with ${prefixes[prefix]}`);
  }
  return given;
}

function randomBase62(length: number): string {
  const chars =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  let result = "";
  const bytes = randomBytes(length);
  for (let i = 0; i < length; i++) {
    result += chars[bytes[i] % 62];
  }
  return result;
}

function create(
  prefix: IdentifierPrefix,
  descending: boolean,
  timestamp?: number,
): string {
  const currentTimestamp = timestamp ?? Date.now();

  if (currentTimestamp !== lastTimestamp) {
    lastTimestamp = currentTimestamp;
    counter = 0;
  }
  counter++;

  let now = BigInt(currentTimestamp) * BigInt(0x1000) + BigInt(counter);

  now = descending ? ~now : now;

  const timeBytes = Buffer.alloc(6);
  for (let i = 0; i < 6; i++) {
    timeBytes[i] = Number((now >> BigInt(40 - 8 * i)) & BigInt(0xff));
  }

  return (
    prefixes[prefix] +
    "_" +
    timeBytes.toString("hex") +
    randomBase62(LENGTH - 12)
  );
}
