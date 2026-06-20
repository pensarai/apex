import { randomBytes } from "node:crypto";

declare const __brand: unique symbol;
type Branded<B extends string> = string & { readonly [__brand]: B };

export type ApprovalId = Branded<"ApprovalId">;
export type ActionId = Branded<"ActionId">;

const stamp = () => `${Date.now()}_${randomBytes(4).toString("hex")}`;

export const mintApprovalId = (): ApprovalId => `apr_${stamp()}` as ApprovalId;
export const mintActionId = (): ActionId => `act_${stamp()}` as ActionId;
export const mintToolCallId = (): string => `tc_${stamp()}`;
