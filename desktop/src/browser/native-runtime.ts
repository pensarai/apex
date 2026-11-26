import { JSCallback } from "bun:ffi";
import { native } from "../../node_modules/electrobun/dist/api/bun/proc/native";

const blockedBridge = new JSCallback(() => {}, {
  args: ["u32", "cstring"],
  returns: "void",
  threadsafe: true,
});
if (!native)
  throw new Error("The embedded browser requires native desktop support.");
const create = native.symbols.initWebview;
native.symbols.initWebview = ((...args: Parameters<typeof create>) => {
  // Electrobun 1.18's bundled Bun can lose the trailing sandbox flag across FFI.
  if (args[19]) {
    args[13] = blockedBridge.ptr;
    args[14] = blockedBridge.ptr;
  }
  return create(...args);
}) as typeof create;
