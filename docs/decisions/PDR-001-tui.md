# PDR-001: Terminal UI over web app or headless CLI

## Context

Apex needs a user interface for driving autonomous pentest agents in real time. The core users — professional pentesters, security engineers, and developers shifting left — need to see live streaming output (recon discoveries, swarm agent logs, finding alerts) as it happens. We had three realistic options: web app, headless CLI, or terminal UI (TUI).

## Decision

We built a TUI using Ink (React for the terminal).

## Rationale

Security practitioners live in the terminal. It is their native environment: Kali VMs, SSH jump hosts, Docker containers, CI pipelines. A web app would require hosting, a browser, and an authenticated account — none of which belong in a pentest workflow. A headless CLI alone cannot surface the rich, live, multi-panel output that makes an autonomous multi-agent run interpretable in real time; without visibility into what's happening, users can't make informed decisions about when to intervene.

The TUI is the right middle ground: rich, live, interactive output with zero browser or server overhead. It runs fully locally, works air-gapped, and composes naturally with other CLI tooling.

## Alternatives considered

- **Web app** — rejected. Requires server infrastructure, browser, hosted auth. Adds operational complexity for users whose environments may be air-gapped or firewalled. Also misaligns with the terminal-native workflow of the target audience.
- **Headless CLI** — rejected as the sole interface. A CLI is useful for scripting and CI but provides no visibility into live agent activity. Without real-time output, users cannot steer or monitor a long-running engagement.

## Consequences

- ✅ Works air-gapped, on Kali, in Docker containers, in CI
- ✅ No hosting, auth infrastructure, or browser required
- ✅ Naturally composable with other terminal tooling
- ⚠️ Harder to build rich data visualizations (charts, graphs) compared to a web UI
- ⚠️ TUI frameworks (Ink) are less mature than web frameworks; layout edge cases require careful handling
