# Example Prompt Injection Library

This directory demonstrates the local library shape expected by Apex.

- `catalog.json` contains safe, model-visible metadata only.
- `payloads/` contains the raw prompt-injection payload text.
- Catalog entries reference payload files with relative `payloadPath` values.

Run Apex with this library by passing:

```sh
/prompt-injection --library ./exmaples/prompt-injection
```

or by setting:

```sh
PENSAR_PROMPT_INJECTION_LIBRARY=./exmaples/prompt-injection
```
