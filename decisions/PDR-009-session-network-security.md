# PDR-009: Harness-owned session network security and OAST routing

## Context

Code-oriented agents can place destinations inside generated scripts and subprocesses. Command-string inspection is useful feedback, but it cannot be the security boundary: it can miss dynamically constructed destinations, and a process with sufficient privilege can bypass an in-process proxy or rewrite firewall rules installed inside its own sandbox.

Offensive testing also needs out-of-band callbacks. Giving the model a third-party OAST tool or a shared collector creates unnecessary data exposure and benchmark-hacking surface. The agent should own its listener and correlation logic while Apex supplies only isolated routing.

## Decision

Apex owns one security policy and callback lease per sandbox session. The session config can request:

- `networkSecurity.egress: "strict"` for default-deny process-tree egress;
- `networkSecurity.allowDns` for controller-owned DNS resolution;
- `networkSecurity.oast` for an opaque callback route and reserved listener port.

The request also carries the normalized destructive and traffic policy:
bounded rate-test authorization, request ceiling, burst, concurrency, and the
always-false availability-impact permission. Programs receive a read-only
summary, but only the controller enforces the effective boundary.

Apex derives allowed destinations from session targets and explicit scope constraints, hashes the complete request into a policy ID, and provisions it through a trusted `SandboxSecurityController`. The controller must apply policy outside the privilege domain of model-authored commands—for example at a container network, VM firewall, network namespace, host firewall, or transparent enforcement proxy.

Strict mode fails closed when no sandbox/controller exists or when the controller cannot attest all of the following:

- the attestation matches the requested policy ID;
- egress is default-deny;
- the boundary covers the full process tree.

Every sandbox command waits for successful provisioning. The resulting wrapper injects immutable `APEX_CALLBACK_URL`, `APEX_CALLBACK_PORT`, and `APEX_CALLBACK_EVENTS_PATH` values into subprocess environments when OAST is enabled. Shell commands, HTTP requests, generated scripts, Playwright, Camoufox, and their descendants therefore share the same external policy boundary.

`SessionOastRouter` allocates a 192-bit opaque route per session, forwards callbacks to the controller-exposed listener address, and writes an NDJSON record before returning. Failed listener delivery still produces an artifact and a `202` response. The router supports either a harness-owned HTTP listener or hosted ingress delivered through `dispatch()`.

`HarnessSandboxSecurityController` composes the platform-specific process enforcer with the provider-neutral OAST router. Platform adapters implement only the privileged enforcement/mapping operation.

## Rationale

**The harness owns policy; the platform owns privilege.** Apex specifies and validates the security outcome without pretending that code running beside the agent can constrain that agent.

**One boundary covers every execution path.** Enforcement is attached to the sandbox process tree, not individual tool implementations or command syntax.

**OAST is infrastructure, not model knowledge.** The model receives an opaque URL and port, writes its listener, and handles correlation. It receives no benchmark answer or collector-side secret.

**Fail-closed rollout.** Existing sessions remain unchanged unless they request network security. Once strict mode is enabled, missing or weak provider support blocks execution rather than silently falling back to source inspection.

## Alternatives considered

- **Expand command parsing to inspect generated scripts** — rejected. Dynamic code, encoded payloads, subprocesses, and alternate runtimes make complete inspection impossible.
- **Set HTTP proxy environment variables** — rejected. Processes can ignore or clear them; this does not cover arbitrary sockets or child processes.
- **Install iptables rules inside the agent sandbox** — rejected. A sufficiently privileged agent process can remove rules in its own namespace.
- **Expose a shared OAST tool directly to the model** — rejected. It couples reasoning to infrastructure, expands schemas, and increases cross-session and benchmark leakage risk.

## Consequences

- ✅ Strict sessions cannot execute until an external process-tree boundary is attested
- ✅ Target scope becomes enforceable for model-authored scripts and descendants
- ✅ OAST routes and artifacts are isolated per session and model-agnostic
- ✅ Console, Daytona, Docker, and local Linux adapters share one Apex contract
- ⚠️ Each sandbox provider must implement a privileged `ProcessEgressEnforcer`
- ⚠️ Browser and package dependencies must be baked into strict sandbox images because arbitrary package-registry egress is denied
- ⚠️ Public callback reachability still depends on the deployment's ingress or relay configuration
