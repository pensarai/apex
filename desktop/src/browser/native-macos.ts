import { dlopen, type Pointer, ptr } from "bun:ffi";
import { BrowserView } from "electrobun/bun";

const objc = dlopen("/usr/lib/libobjc.A.dylib", {
  sel_registerName: { args: ["cstring"], returns: "ptr" },
  objc_getClass: { args: ["cstring"], returns: "ptr" },
  objc_msgSend: { args: ["ptr", "ptr"], returns: "ptr" },
});
// Objective-C tagged pointers must retain all 64 bits across Bun FFI.
const argument = dlopen("/usr/lib/libobjc.A.dylib", {
  objc_msgSend: { args: ["u64", "ptr", "u64"], returns: "u64" },
});
const invocation = dlopen("/usr/lib/libobjc.A.dylib", {
  objc_msgSend: { args: ["u64", "ptr", "ptr", "u64"], returns: "void" },
});
const dispatch = dlopen("/usr/lib/libobjc.A.dylib", {
  objc_msgSend: { args: ["u64", "ptr", "ptr", "ptr", "bool"], returns: "void" },
});
const selector = (name: string) =>
  objc.symbols.sel_registerName(ptr(Buffer.from(`${name}\0`)));
const nsView = selector("nsView");
const window = selector("window");
const contentView = selector("contentView");
const removeView = selector("removeAbstractViewWithId:");
const removeFromSuperview = selector("removeFromSuperview");
const performOnMain = selector(
  "performSelectorOnMainThread:withObject:waitUntilDone:",
);
const invocationClass = objc.symbols.objc_getClass(
  ptr(Buffer.from("NSInvocation\0")),
);
const methodSignature = selector("methodSignatureForSelector:");
const withSignature = selector("invocationWithMethodSignature:");
const setTarget = selector("setTarget:");
const setSelector = selector("setSelector:");
const setArgument = selector("setArgument:atIndex:");
const invoke = selector("invoke");

function untrack(container: Pointer, id: number) {
  const signature = argument.symbols.objc_msgSend(
    container,
    methodSignature,
    removeView,
  );
  const call = argument.symbols.objc_msgSend(
    invocationClass,
    withSignature,
    signature,
  );
  argument.symbols.objc_msgSend(call, setTarget, container);
  argument.symbols.objc_msgSend(call, setSelector, removeView);
  const value = new Uint32Array([id]);
  invocation.symbols.objc_msgSend(call, setArgument, ptr(value), 2);
  dispatch.symbols.objc_msgSend(call, performOnMain, invoke, null, true);
}

const remove = BrowserView.prototype.remove;
BrowserView.prototype.remove = function () {
  if (this.renderer === "cef" && this.sandbox && this.ptr && !this.isRemoved) {
    // Electrobun 1.18 closes the parent NSWindow unless its CEF child is detached first.
    const child = objc.symbols.objc_msgSend(this.ptr, nsView);
    if (child) {
      const owner = objc.symbols.objc_msgSend(child, window);
      const container = owner
        ? objc.symbols.objc_msgSend(owner, contentView)
        : null;
      if (container) untrack(container, this.id);
      dispatch.symbols.objc_msgSend(
        child,
        performOnMain,
        removeFromSuperview,
        null,
        true,
      );
    }
  }
  return remove.call(this);
};
