/**
 * Library barrel (design §3.6). Namespaced per package.json `exports`
 * subpath so unrelated modules can't collide on export names; import the
 * subpath directly (e.g. `@pensar/apex/core/eventBus`) for anything not
 * listed here.
 */

import * as offSecAgent from "./core/agents/offSecAgent";
// biome-ignore lint/style/noRestrictedImports: public library subpath (design §3.6), not an offSecAgent internal
import * as subagentSpawner from "./core/agents/offSecAgent/subagentSpawner";
import * as authenticationAgent from "./core/agents/specialized/authenticationAgent";
import * as findingJudge from "./core/agents/specialized/findingJudge";
import * as patching from "./core/agents/specialized/patching";
import * as whiteboxAttackSurfaceAgent from "./core/agents/specialized/whiteboxAttackSurface";
import * as ai from "./core/ai";
import * as api from "./core/api";
import * as eventBus from "./core/eventBus";
import * as attackSurfaceRegistry from "./core/findings/attackSurfaceRegistry";
import * as findingsRegistry from "./core/findings/registry";
import * as id from "./core/id/id";
import * as observability from "./core/observability";
import * as promptInjections from "./core/prompt-injections";
import * as session from "./core/session";
import * as sessionPersistence from "./core/session/persistence";
import * as toolBackends from "./core/tools/backends";
import * as whiteboxAttackSurfaceWorkflow from "./core/workflows/whiteboxAttackSurface";
import * as cvss from "./lib/cvss";

export {
  ai,
  api,
  attackSurfaceRegistry,
  authenticationAgent,
  cvss,
  eventBus,
  findingJudge,
  findingsRegistry,
  id,
  observability,
  offSecAgent,
  patching,
  promptInjections,
  session,
  sessionPersistence,
  subagentSpawner,
  toolBackends,
  whiteboxAttackSurfaceAgent,
  whiteboxAttackSurfaceWorkflow,
};
