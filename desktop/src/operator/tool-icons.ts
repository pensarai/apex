import {
  AppWindow,
  ArrowRightLeft,
  BookOpen,
  Camera,
  CircleCheck,
  Cookie,
  FileDiff,
  FilePen,
  FilePlus,
  FileText,
  Flag,
  Folder,
  GitBranch,
  Globe,
  type LucideIcon,
  MessageSquare,
  MousePointer2,
  ScanLine,
  Search,
  ShieldAlert,
  Smartphone,
  Terminal,
  Type,
  Wrench,
} from "lucide-react";
import { canonicalToolName } from "./tool-presentation";

const byName: Record<string, LucideIcon> = {
  http_request: ArrowRightLeft,
  execute_command: Terminal,
  read_file: FileText,
  create_file: FilePlus,
  update_file: FilePen,
  write_file: FilePen,
  edit_file: FilePen,
  list_files: Folder,
  glob: Folder,
  grep: Search,
  search_files: Search,
  get_memory: BookOpen,
  list_memories: BookOpen,
  add_memory: BookOpen,
  browser_navigate: AppWindow,
  browser_click: MousePointer2,
  browser_fill: Type,
  browser_type: Type,
  browser_screenshot: Camera,
  browser_snapshot: ScanLine,
  browser_get_cookies: Cookie,
  checkpoint_state: Flag,
  web_search: Globe,
  document_vulnerability: ShieldAlert,
  document_finding: ShieldAlert,
  response: CircleCheck,
  spawn_workspace_agent: GitBranch,
  run_attack_surface: GitBranch,
  spawn_recon_agent: GitBranch,
  spawn_coding_agent: GitBranch,
  spawn_pentest_swarm: GitBranch,
  spawn_pentest_agent: GitBranch,
  run_pentest_workflow: GitBranch,
  delegate_to_auth_subagent: GitBranch,
  task: GitBranch,
};

const byPattern: readonly [RegExp, LucideIcon][] = [
  [/^android_/, Smartphone],
  [/domain/, Globe],
  [/comment/, MessageSquare],
  [/fix|patch/, FileDiff],
  [/repositor/, Folder],
  [/skill/, BookOpen],
];

export function toolIcon(name: string): LucideIcon {
  const canonical = canonicalToolName(name);
  if (Object.hasOwn(byName, canonical)) return byName[canonical];
  for (const [pattern, icon] of byPattern) {
    if (pattern.test(canonical)) return icon;
  }
  return Wrench;
}
