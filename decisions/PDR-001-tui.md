# PDR-001: Terminal UI as the primary interactive interface

## Context

Apex needs a user interface for driving autonomous pentest agents in real time. The core users — professional pentesters, security engineers, and developers shifting left — need to see live streaming output (recon discoveries, swarm agent logs, finding alerts) as it happens. We also ship a headless CLI alongside the TUI for programmatic use, CI integration, and invocation from other coding agents and skills. The question is what the primary *interactive* interface should be.

## Decision

We built a TUI using OpenTUI as the primary interactive interface, shipped alongside a headless CLI for programmatic and integration use cases.

## Rationale

Security practitioners live in the terminal. It is their native environment: Kali VMs, SSH jump hosts, Docker containers, CI pipelines. The TUI surfaces rich, live, multi-panel output — recon discoveries, swarm agent logs, approval gates, finding alerts — that makes an autonomous multi-agent run interpretable and steerable in real time. Without that visibility, users can't make informed decisions about when to intervene.

The headless CLI complements the TUI: it exposes the same agent capabilities for scripting, CI pipelines, and use as a tool from other coding agents and AI skills, without requiring a terminal renderer.

## Alternatives considered

- **Web app** — rejected. Requires server infrastructure, browser, and hosted auth — none of which belong in a pentest workflow. Adds operational complexity for users in air-gapped or firewalled environments, and misaligns with the terminal-native workflow of the target audience.
- **Desktop app (Electron / Tauri)** — rejected. Adds a heavyweight runtime and installer, doesn't work in headless SSH or container environments, and provides no meaningful UX advantage over a TUI for a keyboard-driven security tool. Also incompatible with running on a remote Kali box or inside a CI runner.

## Consequences

- ✅ Works air-gapped, on Kali, in Docker containers, in CI
- ✅ No hosting, auth infrastructure, or browser required
- ✅ Headless CLI enables use from coding agents, AI skills, and CI pipelines
- ⚠️ Harder to build rich data visualizations (charts, graphs) compared to a web UI
- ⚠️ TUI frameworks (OpenTUI) are less mature than web frameworks; layout edge cases require careful handling
