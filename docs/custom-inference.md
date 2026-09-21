# Custom inference endpoints

Apex can run against an OpenAI-compatible **Chat Completions** endpoint. Define a
named provider, the environment variable containing its bearer token, and its
models. No model-discovery endpoint or Pensar login is required.

## Configuration

Add `customProviders` to `~/.pensar/config.json`, preserving the other settings:

```json
{
  "customProviders": {
    "glm-research": {
      "name": "GLM Research",
      "baseUrl": "https://api.z.ai/api/paas/v4",
      "apiKeyEnv": "GLM_RESEARCH_API_KEY",
      "headers": { "Accept-Language": "en-US,en" },
      "requestBody": {
        "temperature": 1,
        "reasoning_effort": "max",
        "thinking": { "type": "enabled", "clear_thinking": false }
      },
      "models": [
        {
          "id": "glm-5.3",
          "contextLength": 1048576,
          "maxOutputTokens": 131072
        }
      ]
    }
  }
}
```

Use the endpoint and limits granted by your provider; the URL above is Z.ai's
public example. A full URL ending in `/chat/completions` is also accepted.
`contextLength` includes input and output; `maxOutputTokens` must be smaller.
Apex uses these limits for context fitting and caps requests accordingly.

Set `GLM_RESEARCH_API_KEY` in the environment that starts Apex. Store the token
through your normal secret mechanism, separately from this configuration. Omit
`apiKeyEnv` for an unauthenticated local server. `headers` is for nonsecret extra
headers; `apiKeyEnv` supplies `Authorization: Bearer ...`.

`requestBody` adds provider-specific fields to every inference request, including
streaming, structured generation, and summarization. Configured fields take
precedence over SDK defaults. Apex retains control of messages, tool definitions,
model identity, streaming, response format, and output limits; those fields cannot
be overridden here. The endpoint must support streaming and function calling.
Structured generation uses JSON mode with Apex validating the returned schema.

The compatible SDK returns GLM reasoning content on subsequent tool turns.
Persisted message histories retain it on resume. Normal context compaction still
replaces old history with a summary; preserved thinking does not disable compaction.

## Headless CLI and workers

Select a provider and its upstream model separately:

```sh
pensar pentest --target http://target.example \
  --model-provider glm-research --model glm-5.3
```

The equivalent model ID is `custom:glm-research:glm-5.3`. This form works with
existing launchers that pass a single `--model` argument:

```sh
pensar pentest --target http://target.example \
  --model custom:glm-research:glm-5.3
```

For workers without a local config file, set `APEX_CUSTOM_PROVIDERS` to the JSON
object **inside** `customProviders`. For example, store that object in a nonsecret
`custom-providers.json` file, then run:

```sh
export APEX_CUSTOM_PROVIDERS="$(cat custom-providers.json)"
pensar -p 'Say hello' --model custom:glm-research:glm-5.3
```

Environment entries replace saved entries with the same provider ID. Explicit
`AIAuthConfig.customProviders` takes precedence for programmatic agent calls.
Missing providers, undeclared models, and missing credential variables fail
explicitly instead of routing to another provider. Child agents inherit the
parent's inference configuration.

An Evalgate worker must supply `APEX_CUSTOM_PROVIDERS`, `GLM_RESEARCH_API_KEY`, and
`MODEL_ID=custom:glm-research:glm-5.3` to its Apex process. The local Evalgate CLI
can pass the same ID with `--model`. Cloud launch catalog validation and container
environment forwarding must also support this configuration in Evalgate; this
Apex change does not alter Evalgate's deployment or launch API.

## Operator model picker

Start Apex with the configuration and credential environment above. `/models`
lists the declared models under **Custom endpoints**, labeled with the provider's
name. Selection and recent-model history work like other models. Provider names
keep identical model IDs on different endpoints distinct. Setup is config/env
based; the provider-management dialog does not yet edit custom entries.

## Optional live check

After setting the configuration and key in the same terminal, run from an Apex
source checkout:

```sh
RUN_CUSTOM_INFERENCE_INTEGRATION=1 \
APEX_CUSTOM_MODEL=custom:glm-research:glm-5.3 \
bun run test src/core/ai/providers/custom.live.test.ts
```

This explicitly enabled test makes real inference requests and exercises one
synthetic echo tool. The ordinary test suite skips it and tests the transport
with mocked responses. For a quick probe, lower the configured output budget
before running the live test.
