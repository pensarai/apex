/**
 * Static Analysis Agent Tools
 *
 * Tool bundles for the 8 static analysis agents.
 */

export { createRepoTools } from './repo-tools';
export { createAnalysisTools, runAllAnalysisTools } from './analysis-tools';
export { createFindingTools } from './finding-tools';

// Re-export tool creation functions
import { createRepoTools } from './repo-tools';
import { createAnalysisTools } from './analysis-tools';
import { createFindingTools } from './finding-tools';
import type { WorkspacePaths } from '../workspace';
import type { ToolAvailability, StaticAnalysisStage } from '../types';

/**
 * Create all tools for a specific agent stage
 */
export function createToolsForStage(
  paths: WorkspacePaths,
  stage: StaticAnalysisStage,
  toolAvailability: ToolAvailability
) {
  const repoTools = createRepoTools(paths);
  const analysisTools = createAnalysisTools(paths, toolAvailability);
  const findingTools = createFindingTools(paths, stage);

  // Return appropriate tools based on stage
  switch (stage) {
    case 'repo-intake':
      return {
        ...repoTools,
      };

    case 'index-graph':
      return {
        list_files: repoTools.list_files,
        read_file: repoTools.read_file,
        search_code: repoTools.search_code,
      };

    case 'analyzer':
      return {
        ...analysisTools,
        list_files: repoTools.list_files,
        read_file: repoTools.read_file,
      };

    case 'spec-synth':
      return {
        read_file: repoTools.read_file,
        search_code: repoTools.search_code,
        run_semgrep: analysisTools.run_semgrep,
        run_codeql: analysisTools.run_codeql,
      };

    case 'vul-rag':
      return {
        list_findings: findingTools.list_findings,
        get_finding: findingTools.get_finding,
        update_finding: findingTools.update_finding,
      };

    case 'localize':
      return {
        read_file: repoTools.read_file,
        search_code: repoTools.search_code,
        list_findings: findingTools.list_findings,
        get_finding: findingTools.get_finding,
        create_finding: findingTools.create_finding,
        update_finding: findingTools.update_finding,
      };

    case 'triage':
      return {
        ...findingTools,
        read_file: repoTools.read_file,
      };

    case 'report':
      return {
        list_findings: findingTools.list_findings,
        get_finding: findingTools.get_finding,
        get_finding_stats: findingTools.get_finding_stats,
        read_file: repoTools.read_file,
      };

    default:
      return {
        ...repoTools,
        ...analysisTools,
        ...findingTools,
      };
  }
}
