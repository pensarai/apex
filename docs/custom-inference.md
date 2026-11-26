# Custom inference endpoints

Apex can run against an OpenAI-compatible **Chat Completions** or **Responses**
endpoint. Define a named provider, the environment variable containing its bearer
token, and its models. No model-discovery endpoint or Pensar login is required.

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
Omitting `apiType` selects Chat Completions for existing configurations.

Set `GLM_RESEARCH_API_KEY` in the environment that starts Apex. Store the token
through your normal secret mechanism, separately from this configuration. Omit
`apiKeyEnv` for an unauthenticated local server. `headers` is for nonsecret extra
headers; `apiKeyEnv` supplies `Authorization: Bearer ...`.

For Chat Completions, `requestBody` adds provider-specific fields to every
inference request, including streaming, structured generation, and summarization.
Configured fields take precedence over SDK defaults. Apex retains control of
messages, tool definitions,
model identity, streaming, response format, and output limits; those fields cannot
be overridden here. The endpoint must support streaming and function calling.
Structured generation uses JSON mode with Apex validating the returned schema.

For endpoints that require an explicit request for streamed token counts, set
`includeUsage: true` on the provider. Apex sends
`stream_options: { include_usage: true }` on streaming Chat Completions requests
and preserves the returned input, output, and cached-input usage. Omitted or
`false` leaves the request unchanged for endpoints that do not support this
option. This setting does not apply to the Responses API or non-streaming calls.

The compatible SDK returns GLM reasoning content on subsequent tool turns.
Persisted message histories retain it on resume. Normal context compaction still
replaces old history with a summary; preserved thinking does not disable compaction.

### Responses endpoints

For an endpoint that implements the OpenAI Responses API, set `apiType` to
`responses` and use the API base URL (without `/responses`). You can set an
optional `reasoningEffort` on each model:

```json
{
  "customProviders": {
    "research": {
      "name": "Research endpoint",
      "apiType": "responses",
      "baseUrl": "https://api.openai.com/v1",
      "apiKeyEnv": "RESEARCH_API_KEY",
      "models": [
        {
          "id": "your-model-id",
          "contextLength": 200000,
          "maxOutputTokens": 32000,
          "reasoningEffort": "high",
          "supportedReasoningEfforts": ["low", "medium", "high"]
        }
      ]
    }
  }
}
```

Replace the model ID and limits with values for your endpoint. Set
`RESEARCH_API_KEY` in the environment that starts Apex; this provider does not
use the saved OpenAI key. Responses providers require `apiKeyEnv`. Supported
effort values are `none`, `minimal`, `low`, `medium`, `high`, `xhigh`, and `max`;
the endpoint decides which values a model accepts. Omit `reasoningEffort` to
leave the effort choice to the endpoint. `requestBody` is available only for
Chat Completions providers.

Declare `supportedReasoningEfforts` only with levels verified for that endpoint
and model. This enables the TUI effort selector and `--effort` overrides; an
explicit selection takes precedence over `reasoningEffort`. The configured
default must belong to the declared list. Without that metadata, Apex keeps the
endpoint's configured behavior and hides the effort control. Chat Completions
endpoints continue to use their explicit `requestBody` configuration.

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

### Baseten

With `BASETEN_API_KEY` set on a trusted workstation, the model picker discovers production vLLM deployments whose configuration declares an OpenAI chat route, served model name, and context length. Discovery reads management metadata and leaves sleeping GPUs asleep. Select the deployment in the picker or pass its displayed model ID to the CLI.

For an invoke-only key or another OpenAI-compatible Baseten server, set `BASETEN_BASE_URL` to its API base, such as `https://model-<model-id>.api.baseten.co/deployment/<deployment-id>/sync/v1`. Apex reads the served models from that endpoint's `/models` route. Contacting a sleeping endpoint can wake it. When a Baseten request waits a second for its first text, reasoning, or tool output, Apex shows a pulsing diamond and the elapsed time since the request started. After a wait of five seconds or more, the main chat shows the measured time to first output.
