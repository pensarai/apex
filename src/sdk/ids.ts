import { ascending, schema as prefixSchema } from "../core/id/id.ts";

declare const __brand: unique symbol;
type Brand<T, B> = T & { readonly [__brand]: B };

export type SessionID = Brand<string, "SessionID">;
export type NodeID = Brand<string, "NodeID">;
export type MessageID = Brand<string, "MessageID">;
export type PartID = Brand<string, "PartID">;
export type EventID = Brand<string, "EventID">;

export const mintSessionID = (given?: string): SessionID =>
  ascending("session", given) as SessionID;
export const mintNodeID = (given?: string): NodeID =>
  ascending("node", given) as NodeID;
export const mintMessageID = (given?: string): MessageID =>
  ascending("message", given) as MessageID;
export const mintPartID = (given?: string): PartID =>
  ascending("part", given) as PartID;
export const mintEventID = (given?: string): EventID =>
  ascending("event", given) as EventID;

export const SessionIDSchema = prefixSchema("session").transform(
  (v) => v as SessionID,
);
export const NodeIDSchema = prefixSchema("node").transform((v) => v as NodeID);
export const MessageIDSchema = prefixSchema("message").transform(
  (v) => v as MessageID,
);
export const PartIDSchema = prefixSchema("part").transform((v) => v as PartID);
export const EventIDSchema = prefixSchema("event").transform(
  (v) => v as EventID,
);

export const isSessionID = (v: string): v is SessionID => v.startsWith("ses_");
export const isNodeID = (v: string): v is NodeID => v.startsWith("nod_");
export const isMessageID = (v: string): v is MessageID => v.startsWith("msg_");
export const isPartID = (v: string): v is PartID => v.startsWith("prt_");
export const isEventID = (v: string): v is EventID => v.startsWith("evt_");
