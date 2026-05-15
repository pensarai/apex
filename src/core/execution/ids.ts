import * as Identifier from "../id/id";

declare const __brand: unique symbol;
type Brand<B> = { readonly [__brand]: B };

export type SessionID = string & Brand<"SessionID">;
export type NodeID = string & Brand<"NodeID">;
export type MessageID = string & Brand<"MessageID">;
export type PartID = string & Brand<"PartID">;
export type EventID = string & Brand<"EventID">;

export const SessionIdSchema = Identifier
  .schema("session")
  .transform((s) => s as SessionID);
export const NodeIdSchema = Identifier
  .schema("node")
  .transform((s) => s as NodeID);
export const MessageIdSchema = Identifier
  .schema("message")
  .transform((s) => s as MessageID);
export const PartIdSchema = Identifier
  .schema("part")
  .transform((s) => s as PartID);
export const EventIdSchema = Identifier
  .schema("event")
  .transform((s) => s as EventID);

export const newSessionId = (): SessionID =>
  Identifier.ascending("session") as SessionID;
export const newNodeId = (): NodeID => Identifier.ascending("node") as NodeID;
export const newMessageId = (): MessageID =>
  Identifier.ascending("message") as MessageID;
export const newPartId = (): PartID => Identifier.ascending("part") as PartID;
export const newEventId = (): EventID =>
  Identifier.ascending("event") as EventID;
