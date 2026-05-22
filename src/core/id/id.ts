import { randomBytes } from "crypto";
import z from "zod";

const prefixes = {
  session: "ses",
  message: "msg",
  permission: "per",
  user: "usr",
  part: "prt",
} as const;

export type IdentifierPrefix = keyof typeof prefixes;

declare const __brand: unique symbol;
type Brand<K extends IdentifierPrefix> = { readonly [__brand]: K };

export type SessionId = string & Brand<"session">;
export type MessageId = string & Brand<"message">;
export type PartId = string & Brand<"part">;

export function schema(prefix: IdentifierPrefix) {
  return z.string().startsWith(prefixes[prefix] + "_");
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

export function newSessionId(): SessionId {
  return descending("session") as SessionId;
}

export function newMessageId(): MessageId {
  return descending("message") as MessageId;
}

export function newPartId(): PartId {
  return descending("part") as PartId;
}

export function isSessionId(v: unknown): v is SessionId {
  return typeof v === "string" && hasPrefix(v, "session");
}

export function isMessageId(v: unknown): v is MessageId {
  return typeof v === "string" && hasPrefix(v, "message");
}

export function isPartId(v: unknown): v is PartId {
  return typeof v === "string" && hasPrefix(v, "part");
}

function hasPrefix(v: string, prefix: IdentifierPrefix): boolean {
  const expected = prefixes[prefix] + "_";
  return v.startsWith(expected) && v.length === expected.length + LENGTH;
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
