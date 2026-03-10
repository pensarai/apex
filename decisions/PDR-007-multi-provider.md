# PDR-007: Multi-provider AI model support

## Context

Apex depends on a large language model to power its agents. We need to decide whether to hardcode a single provider or support multiple (Anthropic, OpenAI, AWS Bedrock, vLLM / self-hosted). Supporting multiple providers adds configuration complexity; picking one simplifies the stack but limits who can use Apex.

## Decision

Apex supports multiple AI providers configurable via the Provider Manager. The recommended default is Anthropic — as of March 2026, Claude Opus delivers the strongest performance for offensive security tasks.

## Rationale

**Air-gapped and classified environments.** Many security-sensitive organizations — government, defense, financial services — cannot send target data to any external API. For these deployments, self-hosted models via vLLM are the only viable option. Without local model support, Apex is unusable in the environments where rigorous pentesting is most needed.

**Provider availability.** Users may already have credits, enterprise agreements, or existing technical access to one provider but not another. Forcing a single provider creates an unnecessary adoption barrier.

Provider support is a pragmatic accommodation of deployment reality, not an endorsement that all providers are equivalent. Model quality varies significantly — Anthropic consistently outperforms alternatives on complex offensive security reasoning tasks. This should be the default recommendation in all documentation and setup flows.

## Alternatives considered

- **Anthropic-only** — rejected. Blocks adoption in air-gapped and classified environments, which are core use cases for the target audience.
- **Expose raw model selection without a recommended default** — rejected. Leaving the choice fully open leads users to pick suboptimal models. We should guide toward the best-performing option while preserving flexibility.

## Consequences

- ✅ Works in air-gapped and classified environments via vLLM / self-hosted models
- ✅ No hard dependency on any single provider's availability or pricing
- ✅ Users with existing provider agreements can use Apex without new accounts
- ⚠️ Provider configuration is additional onboarding friction for new users
- ⚠️ Output quality varies by provider; support burden increases when users report issues on non-recommended providers
- ⚠️ Must maintain provider abstraction layer and test across providers when the AI SDK changes
