import type { Component, Control, Topology } from "./types";

export const INTERNET = "__internet";

export function controlsOn(topology: Topology, id: string): Control[] {
  return topology.controls.filter((c) => c.appliesTo.includes(id));
}

export function publicEntrypoints(topology: Topology): Component[] {
  return topology.components.filter(
    (a) => a.kind === "entrypoint" && a.exposure === "public",
  );
}
