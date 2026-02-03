import os from "os";
import path from "path";
import fs from "fs/promises";
import { mkdir } from "fs/promises";
import { Lock } from "../../util/lock";
import { NamedError } from "../../util/errors";
import { z } from "zod";
import type {
  MemoryTool,
  Technique,
  MemoryFinding,
  MemoryIndex,
  SearchResult,
} from "./types";

export namespace Memory {
  export const NotFoundError = NamedError.create(
    "MemoryNotFoundError",
    z.object({ message: z.string() })
  );

  function getMemoryDir(): string {
    return path.join(os.homedir(), ".pensar", "memory");
  }

  function getWorkspaceDir(workspace: string): string {
    return path.join(getMemoryDir(), workspace);
  }

  async function ensureWorkspace(workspace: string): Promise<void> {
    const wsDir = getWorkspaceDir(workspace);
    await mkdir(path.join(wsDir, "tools"), { recursive: true });
    await mkdir(path.join(wsDir, "techniques"), { recursive: true });
    await mkdir(path.join(wsDir, "findings"), { recursive: true });
  }

  async function getIndex(workspace: string): Promise<MemoryIndex> {
    const indexPath = path.join(getWorkspaceDir(workspace), "index.json");
    try {
      using _ = await Lock.read(indexPath);
      const content = await Bun.file(indexPath).json();
      return content as MemoryIndex;
    } catch {
      return {
        workspace,
        lastUpdated: new Date().toISOString(),
        tools: [],
        techniques: [],
        findings: [],
      };
    }
  }

  async function updateIndex(
    workspace: string,
    updater: (index: MemoryIndex) => void
  ): Promise<void> {
    const indexPath = path.join(getWorkspaceDir(workspace), "index.json");
    using _ = await Lock.write(indexPath);
    let index: MemoryIndex;
    try {
      index = await Bun.file(indexPath).json();
    } catch {
      index = {
        workspace,
        lastUpdated: new Date().toISOString(),
        tools: [],
        techniques: [],
        findings: [],
      };
    }
    updater(index);
    index.lastUpdated = new Date().toISOString();
    await Bun.write(indexPath, JSON.stringify(index, null, 2));
  }

  export async function storeTool(
    workspace: string,
    tool: MemoryTool
  ): Promise<void> {
    await ensureWorkspace(workspace);
    const toolPath = path.join(
      getWorkspaceDir(workspace),
      "tools",
      `${tool.name}.json`
    );
    using _ = await Lock.write(toolPath);
    await Bun.write(toolPath, JSON.stringify(tool, null, 2));
    await updateIndex(workspace, (idx) => {
      if (!idx.tools.includes(tool.name)) {
        idx.tools.push(tool.name);
      }
    });
  }

  export async function getTool(
    workspace: string,
    name: string
  ): Promise<MemoryTool | null> {
    const toolPath = path.join(
      getWorkspaceDir(workspace),
      "tools",
      `${name}.json`
    );
    try {
      using _ = await Lock.read(toolPath);
      return (await Bun.file(toolPath).json()) as MemoryTool;
    } catch {
      return null;
    }
  }

  export async function listTools(workspace: string): Promise<string[]> {
    const index = await getIndex(workspace);
    return index.tools;
  }

  export async function storeTechnique(
    workspace: string,
    technique: Technique
  ): Promise<void> {
    await ensureWorkspace(workspace);
    const techPath = path.join(
      getWorkspaceDir(workspace),
      "techniques",
      `${technique.id}.json`
    );
    using _ = await Lock.write(techPath);
    await Bun.write(techPath, JSON.stringify(technique, null, 2));
    await updateIndex(workspace, (idx) => {
      if (!idx.techniques.includes(technique.id)) {
        idx.techniques.push(technique.id);
      }
    });
  }

  export async function getTechnique(
    workspace: string,
    id: string
  ): Promise<Technique | null> {
    const techPath = path.join(
      getWorkspaceDir(workspace),
      "techniques",
      `${id}.json`
    );
    try {
      using _ = await Lock.read(techPath);
      return (await Bun.file(techPath).json()) as Technique;
    } catch {
      return null;
    }
  }

  export async function storeFinding(
    workspace: string,
    finding: MemoryFinding
  ): Promise<void> {
    await ensureWorkspace(workspace);
    const findingPath = path.join(
      getWorkspaceDir(workspace),
      "findings",
      `${finding.id}.json`
    );
    using _ = await Lock.write(findingPath);
    await Bun.write(findingPath, JSON.stringify(finding, null, 2));
    await updateIndex(workspace, (idx) => {
      if (!idx.findings.includes(finding.id)) {
        idx.findings.push(finding.id);
      }
    });
  }

  export async function search(
    workspace: string,
    query: string,
    options?: { types?: ("tool" | "technique" | "finding")[]; limit?: number }
  ): Promise<SearchResult[]> {
    const results: SearchResult[] = [];
    const types = options?.types || ["tool", "technique", "finding"];
    const limit = options?.limit || 20;
    const queryLower = query.toLowerCase();
    const queryTerms = queryLower.split(/\s+/);

    const scoreMatch = (text: string): number => {
      const textLower = text.toLowerCase();
      let score = 0;
      for (const term of queryTerms) {
        if (textLower.includes(term)) {
          score += textLower === term ? 10 : 5;
        }
      }
      return score;
    };

    const index = await getIndex(workspace);

    if (types.includes("tool")) {
      for (const name of index.tools) {
        const tool = await getTool(workspace, name);
        if (tool) {
          const score =
            scoreMatch(tool.name) +
            scoreMatch(tool.description) +
            tool.tags.reduce((s, t) => s + scoreMatch(t), 0);
          if (score > 0) {
            results.push({ type: "tool", id: name, score, data: tool });
          }
        }
      }
    }

    if (types.includes("technique")) {
      for (const id of index.techniques) {
        const tech = await getTechnique(workspace, id);
        if (tech) {
          const score =
            scoreMatch(tech.vulnerabilityClass) +
            scoreMatch(tech.context) +
            scoreMatch(tech.payload) +
            tech.tags.reduce((s, t) => s + scoreMatch(t), 0);
          if (score > 0) {
            results.push({ type: "technique", id, score, data: tech });
          }
        }
      }
    }

    if (types.includes("finding")) {
      for (const id of index.findings) {
        const finding = await getFinding(workspace, id);
        if (finding) {
          const score =
            scoreMatch(finding.title) +
            scoreMatch(finding.vulnerabilityClass) +
            scoreMatch(finding.endpoint);
          if (score > 0) {
            results.push({ type: "finding", id, score, data: finding });
          }
        }
      }
    }

    results.sort((a, b) => b.score - a.score);
    return results.slice(0, limit);
  }

  async function getFinding(
    workspace: string,
    id: string
  ): Promise<MemoryFinding | null> {
    const findingPath = path.join(
      getWorkspaceDir(workspace),
      "findings",
      `${id}.json`
    );
    try {
      using _ = await Lock.read(findingPath);
      return (await Bun.file(findingPath).json()) as MemoryFinding;
    } catch {
      return null;
    }
  }

  export async function incrementToolUsage(
    workspace: string,
    name: string
  ): Promise<void> {
    const tool = await getTool(workspace, name);
    if (tool) {
      tool.usageCount++;
      await storeTool(workspace, tool);
    }
  }
}

export * from "./types";
