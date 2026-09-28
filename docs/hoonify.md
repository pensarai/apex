# Hoonify inference

Hoonify is a built-in Apex provider using Vercel AI SDK's existing
`@ai-sdk/openai-compatible` adapter. Requests go directly to
`https://api.hoonify.ai/v1/chat/completions` with your Hoonify bearer key.
No extra SDK or `customProviders` definition is needed.

## Connect and select a model

1. Create a key for your subscription at [app.hoonify.ai](https://app.hoonify.ai).
2. In Apex, open `/providers`, choose **Hoonify**, and enter the key. Apex checks
   access by loading `/v1/models` before saving it locally, like other providers.
3. Choose a model under **Hoonify** in `/models`.

Alternatively, set `HOONIFY_API_KEY` in the environment that launches Apex.
Environment keys are used when no saved `hoonifyAPIKey` exists; setting an
environment key does not save it to disk.

Apex discovers the models available to your key and uses each returned `id`
unchanged. Hoonify's documentation uses both short and organization-qualified
IDs, so copy the exact ID from your catalog rather than inferring an alias.
Apex prefixes selections with `hoonify:` to distinguish the same model hosted
by different providers; that prefix is removed before the request is sent.

## Headless commands and programmatic use

With `HOONIFY_API_KEY` set, pass a model ID from your catalog:

```sh
pensar pentest --target https://your-authorized-target.example \
  --model-provider hoonify --model '<catalog-model-id>'

# Equivalent single model argument for existing launchers:
pensar pentest --target https://your-authorized-target.example \
  --model 'hoonify:<catalog-model-id>'
```

Programmatic callers should use `buildAuthConfig(await config.get())`, as the
CLI does. This includes the discovered catalog snapshot used for context fitting
and child-agent inference. A direct `AIAuthConfig` can instead supply
`hoonifyAPIKey` and `hoonifyModels` loaded by `loadHoonifyModels` from
`src/core/hoonify.ts`.

Missing keys, unavailable model IDs, and catalog failures produce errors rather
than sending a Hoonify selection to another provider. Existing provider default
priorities remain ahead of Hoonify; select Hoonify explicitly when other keys are
also configured.

## Catalog and token limits

When Hoonify is configured, loading Apex config also loads its authenticated
catalog. Successful results are cached in memory for five minutes and scoped to
the current key; concurrent loads share one request. Reconnecting in `/providers`
forces a refresh. Catalog requests time out after 15 seconds. Catalog failures
are shown in `/models`; other configured providers remain usable. Neither the
catalog nor catalog errors are persisted to the config file.

When supplied, the catalog's `context_window` is the total input-plus-output
window, and Apex uses it for context fitting and compaction. The live API can
also return the standard OpenAI model-list fields (`id`, `object`, `created`,
`owned_by`) without limits. When metadata is absent for `zai-org/GLM-5.2`, Apex
uses a **provisional 512,000-token context budget** pending confirmation of the
deployment's exact limit. The public catalog's model capacity can differ from
the deployed limit. An API-supplied `context_window` takes precedence over this
default, including an exact 524,288-token value if returned by the service.
Model discovery still comes from the authenticated API; this default does not
add models to the picker. No manual override is needed for GLM-5.2.

Models with neither API metadata nor a model-specific default retain a
**32,768-token local context budget**. That fallback can trigger summarization
even for a short message because the operator's prompt and tool overhead can
exceed it. You can set an endpoint-specific limit for any catalog model:

```sh
# Optional example: use a smaller context budget for this deployment.
export HOONIFY_CONTEXT_WINDOWS='{"zai-org/GLM-5.2":131072}'
bun run start
```

Use the exact upstream ID from `/models`, without Apex's `hoonify:` prefix.
The override takes precedence over API metadata, model defaults, and the
fallback, and applies only to matching catalog models. It does not add models,
change keys, or raise the output-token cap. Restart Apex after changing it.
Unset `HOONIFY_CONTEXT_WINDOWS` to restore the normal lookup. Malformed JSON or
non-integer limits produce a configuration error.

The public API documentation does **not** specify a per-model maximum output
length. Until Hoonify confirms those
limits, Apex caps each response at **4,096 tokens**, reduced to one quarter of
the context window for smaller models. This is an Apex request budget, not an
advertised Hoonify model capability. Long reasoning or code responses can hit
that cap. Confirm the deployed output limits before raising it.

Hoonify documents streaming, tools, and structured output support. Apex uses
Chat Completions for ordinary responses, tool turns, summaries, and JSON Schema
generation. The compatible adapter preserves `reasoning_content` through tool
history and serialized resume. No GLM-specific thinking defaults are imposed.
Hoonify currently documents text-only API inputs.

## Optional live check

After setting the key and selecting an exact ID from your subscription's catalog:

```sh
RUN_HOONIFY_INTEGRATION=1 \
HOONIFY_TEST_MODEL='<catalog-model-id>' \
bun run test src/core/ai/providers/hoonify.live.test.ts
```

This makes real, billable inference requests for a synthetic echo tool, a
conversation follow-up, and schema-constrained JSON. It does not access a test
target. Ordinary tests skip it and validate request/response behavior with
fixtures; those tests do not establish live Hoonify compatibility.

For a catalog-format issue, run `bun scripts/diagnose-hoonify.ts` in the terminal
where `HOONIFY_API_KEY` is exported. It prints the HTTP status and response field
names/types without printing credentials or response values.

## References

- [Hoonify OpenAI compatibility](https://hoonify.ai/docs/sdks/openai-compatibility)
- [Hoonify model catalog API](https://hoonify.ai/docs/api/models)
- [Hoonify Chat Completions API](https://hoonify.ai/docs/api/chat-completions)
- [Vercel AI SDK OpenAI-compatible provider](https://ai-sdk.dev/providers/openai-compatible-providers)
