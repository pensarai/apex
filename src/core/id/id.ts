import { randomBytes } from "node:crypto";
import z from "zod";

const prefixes = {
  session: "ses",
  message: "msg",
  permission: "per",
  user: "usr",
  part: "prt",
} as const;

export type IdentifierPrefix = keyof typeof prefixes;

export function schema(prefix: IdentifierPrefix) {
  return z.string().startsWith(prefixes[prefix]);
}

const LENGTH = 26;

let lastTimestamp = 0;
let counter = 0;

function ascending(prefix: IdentifierPrefix, given?: string) {
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

// ---------------------------------------------------------------------------
// Branded identity types + convenience minters / guards
// ---------------------------------------------------------------------------
// Nominal typing only — prevents e.g. a messageId being passed where a
// sessionId is expected. Runtime value is still a plain prefixed-ULID string.

/** A session identifier: `ses_<time><random>`. */
export type SessionID = string & { readonly __brand: "SessionID" };
/** A message identifier: `msg_<time><random>`. */
export type MessageID = string & { readonly __brand: "MessageID" };
/** A part identifier: `prt_<time><random>`. */
export type PartID = string & { readonly __brand: "PartID" };

/** Mint a fresh, time-descending session id. */
export const newSessionId = (): SessionID => descending("session") as SessionID;
/** Mint a fresh, time-descending message id. */
export const newMessageId = (): MessageID => descending("message") as MessageID;
/** Mint a fresh, time-descending part id. */
export const newPartId = (): PartID => descending("part") as PartID;

/** Runtime guard: is this string a session id? */
export const isSessionId = (s: string): s is SessionID =>
  s.startsWith(`${prefixes.session}_`);
/** Runtime guard: is this string a message id? */
export const isMessageId = (s: string): s is MessageID =>
  s.startsWith(`${prefixes.message}_`);
/** Runtime guard: is this string a part id? */
export const isPartId = (s: string): s is PartID =>
  s.startsWith(`${prefixes.part}_`);

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
