# Model effort and thinking

Apex resolves reasoning capabilities for the exact model and provider route.
The same resolver supplies picker choices, CLI validation, and provider request
options. Unknown models keep their existing provider behavior and have no control.
An explicit unsupported selection fails locally before inference.

## Use

Open `/models`, select a model, and use **←/→** to cycle its **Effort** or
**Extended Thinking** setting. The arrows work immediately, including while the
search box has focus. Enter on a provider expands or collapses it; Enter on the
selected model closes the picker. `default` uses the reviewed model default;
optional older Claude thinking remains off by default. The active selection also
appears beside the model in the input bar.

```sh
pensar -p 'Review the current changes' --model gpt-6.1-sol --effort low
pensar pentest --target https://example.test --model claude-opus-5-5 --effort medium
pensar -p 'Review the current changes' --model claude-sonnet-4-5 --extended-thinking
pensar -p 'Review the current changes' --model gemini-2.5-flash --no-extended-thinking
```

These flags apply to headless operator, pentest, targeted-pentest, and threat-model
commands. They are mutually exclusive. The library accepts `reasoning` with the
same values on agent, workflow, streaming, and structured-generation inputs.

Preferences live in `modelReasoning[modelId]` in the Apex config. An explicit CLI
flag overrides the saved preference. Supported legacy `reasoningEnabled` and
`openAIReasoningEffort` preferences are read when no model-specific value exists;
the old `ultra` alias becomes `max` where supported. Invalid saved preferences
fall back to `default`. Legacy library inputs remain accepted, with `reasoning`
taking precedence when supplied. Saved legacy preferences and library inputs use
one compatibility conversion, including the historical Concentrate GLM effort
remapping; unsupported explicit new selections are still rejected.

Sessions persist `{ model, setting }` under `config.modelReasoning`. Resuming the
same model restores the setting through both generic and targeted-pentest APIs;
an explicit `reasoning` overrides it. A different model falls back to legacy
inputs and that model's compatibility defaults. Only an explicit root override
updates an existing session's preference; compatibility defaults and delegated
children do not rewrite it. Children receive the parent's canonical setting.
Streaming, structured output, tool repair, and compaction apply the same selection. Manual thinking budgets are bounded by the
actual output limit, including the smaller compaction limit. OTel generation
metadata records `reasoningRequested` and `reasoningParameters` beside normal
usage and latency data.

## Capability sources

Reviewed on 2026-10-21. `src/core/ai/reasoning.ts` contains native API rules;
`src/core/ai/models/openrouter-reasoning.json` contains route-specific metadata.

| Route                                               | Control and request representation                                                              |
| --------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| OpenAI and known Responses routes                   | Model-specific effort values → `reasoning.effort`                                               |
| Claude direct, Bedrock, Pensar                      | Adaptive thinking plus effort where supported; manual thinking toggle for older models          |
| Google GenerateContent                              | Model-specific `thinkingLevel`, or dynamic/off budget for supported Gemini 2.5 Flash models     |
| OpenRouter                                          | Published supported efforts, defaults, and mandatory-thinking metadata → `reasoning`            |
| Custom Responses                                    | Explicit `supportedReasoningEfforts` configuration; see [custom inference](custom-inference.md) |
| Unknown, local, and undeclared compatible endpoints | No inferred control; existing defaults/configuration retained                                   |

Provider documentation: [OpenAI reasoning](https://developers.openai.com/api/docs/guides/reasoning#reasoning-effort),
[Claude effort](https://platform.claude.com/docs/en/build-with-claude/effort),
[Claude thinking](https://platform.claude.com/docs/en/build-with-claude/thinking),
[Google thinking](https://ai.google.dev/gemini-api/docs/generate-content/thinking),
and [OpenRouter reasoning metadata](https://openrouter.ai/docs/guides/best-practices/reasoning-tokens).

## Maintenance

After updating the model catalog, refresh the public OpenRouter metadata:

```sh
bun run generate:reasoning
bunx biome format --write src/core/ai/models/openrouter-reasoning.json
```

The script reads the public models endpoint without credentials, validates known
effort values, and writes a reviewable snapshot for Apex's catalog. Missing
metadata is stored as `null`, so capability gaps are visible. Runtime selection
does not need a network call. New metadata values fail the refresh until the
resolver and transport support them.

For native providers, review the linked documentation and the installed SDK's
request schema when adding a model. Add only verified values for that route.
An SDK's permissive model-name type is not evidence of server support. Keep
unsupported values out of the picker instead of trying them and retrying on 400s.

Run the reasoning and CLI tests after changes, then the repository checks. The
tests cover every displayed catalog choice, mandatory thinking, actual serialized
SDK requests, provider-routing merges, custom overrides, session restoration,
worker inheritance, and keyboard behavior at two terminal sizes.

Effort labels are not comparable units of compute across providers. Use task
evals with success rate, elapsed time, and token cost to choose a level; Apex
does not assume a log-linear performance curve or automatically raise effort.
