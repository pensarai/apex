// The package's public API surface.
//
// Two consumers:
// 1. External programmatic users — should import from "./core/api" (this barrel).
// 2. src/cli.ts — uses dynamic per-feature imports
//    (await import("./core/api/<feature>")) so `bun build --splitting`
//    produces per-feature chunks. Routing those through this barrel would
//    eliminate the split. The lint rule for module barriers exempts this.
export * from "./attackSurface";
export * from "./authentication";
export * from "./benchmark";
export * from "./blackboxPentest";
export * from "./constants";
export * from "./environment";
export * from "./issues";
export * from "./offesecAgent";
export * from "./patching";
export * from "./targetedPentest";
export * from "./threatModel";
