import { z } from "zod";

// ---------------------------------------------------------------------------
// Plugin phases
// ---------------------------------------------------------------------------

export const PluginPhaseSchema = z.enum(["recon", "test", "all"]);
export type PluginPhase = z.infer<typeof PluginPhaseSchema>;

// ---------------------------------------------------------------------------
// Manifest schema (validated with Zod at load time)
// ---------------------------------------------------------------------------

export const PluginContextEntrySchema = z.object({
  file: z.string(),
  description: z.string().optional(),
  phases: z.array(PluginPhaseSchema),
  priority: z.number().default(0),
});

export const PluginDependencySchema = z.object({
  /** CLI binary name that must be on $PATH (e.g. "aws", "vercel") */
  binary: z.string().optional(),
  /** Human-readable install hint shown when missing */
  installHint: z.string().optional(),
});

export const PluginManifestSchema = z.object({
  name: z.string().regex(/^[a-z0-9-]+$/, "Must be kebab-case"),
  displayName: z.string(),
  description: z.string(),
  version: z.string(),
  /** CLI dependencies that must be installed for this plugin to load */
  requires: z.array(PluginDependencySchema).default([]),
  provides: z.object({
    context: z.array(PluginContextEntrySchema).default([]),
  }),
});

export type PluginManifest = z.infer<typeof PluginManifestSchema>;

// ---------------------------------------------------------------------------
// Runtime state after loading
// ---------------------------------------------------------------------------

export interface ResolvedContextFile {
  absolutePath: string;
  description: string;
  phases: PluginPhase[];
  priority: number;
}

export interface LoadedPlugin {
  manifest: PluginManifest;
  basePath: string;
  enabled: boolean;
  contextFiles: ResolvedContextFile[];
}
