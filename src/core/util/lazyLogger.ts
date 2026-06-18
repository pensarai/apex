import type { createLogger as CreateLogger } from "../logger/structured";

type StructuredLogger = ReturnType<typeof CreateLogger>;

/**
 * Lazily-instantiated scoped logger.
 *
 * The logger barrel transitively imports much of the app, so a module-top
 * `createLogger(...)` call can dereference the factory during a
 * circular-import initialization window. This helper takes a factory and
 * defers invoking it until first use, keeping
 * `const log = scopedLogger(() => createLogger("scope"))` safe at module top.
 *
 * This module imports only a TYPE from the logger, so it is never pulled into
 * the logger's runtime import cycle.
 */
export function scopedLogger(
  factory: () => StructuredLogger,
): StructuredLogger {
  let instance: StructuredLogger | undefined;
  const get = (): StructuredLogger => (instance ??= factory());

  return new Proxy({} as StructuredLogger, {
    get(_target, prop) {
      const inst = get();
      const value = inst[prop as keyof StructuredLogger];
      return typeof value === "function"
        ? (value as (...args: unknown[]) => unknown).bind(inst)
        : value;
    },
  });
}
