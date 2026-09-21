import type { ToolContext } from "../../agents/offSecAgent/tools/types";
import { LocalBackends } from "./local";
import type { ToolBackends } from "./types";

const localByContext = new WeakMap<ToolContext, ToolBackends>();

/** The backends a tool should execute against: injected, else local (memoised per context). */
export function resolveBackends(ctx: ToolContext): ToolBackends {
  if (ctx.backends) return ctx.backends;
  let local = localByContext.get(ctx);
  if (!local) {
    local = LocalBackends(ctx);
    localByContext.set(ctx, local);
  }
  return local;
}
