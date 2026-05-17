# DESIGN.md

UX rules for `sllm` (CLI) and the chat TUI. No GUI in v1. Anyone adding a
user-visible string should read this first.

## Command grammar

```
sllm <noun> <verb> [args] [flags]
```

Examples:

```
sllm models list
sllm models pull TheBloke/foo:bar.gguf
sllm models rm bar
sllm chat --model bar
sllm admin sessions list
sllm debug doctor
```

Top-level verbs that don't fit the noun/verb pattern (`keygen`, `trust`,
`chat`, `complete`, `system`) stay flat for ergonomic reasons.

## Exit codes

| code | meaning |
|-----:|---------|
| 0    | success |
| 1    | runtime error reported by the server (network, auth, model) |
| 2    | bad invocation (missing args, bad pubkey) |
| 130  | interrupted (Ctrl-C) |

## Rich theme

Single `Console` instance. Colors are semantic, not decorative:

- `green` — success.
- `yellow` — warning, or an `ErrorCode` value when reporting a known error.
- `red` — failure, refusal, "stop".
- `cyan` — values the user might copy (keys, IDs, URLs).
- `dim` — hints, transient state ("history cleared").

Don't use bold + color together unless you're titling a section.

## Tables

Use `rich.table.Table` for any output that's structured. First column is
always the identifier; subsequent columns sort from "most-changing" to
"least-changing" (state, size, queue depth, repo). Numbers are
right-aligned and formatted with units (GB, ms).

## Errors

Errors flow through `SecureLLMError` and print as:

```
error <error_code>: <message>
```

Yellow `<error_code>` (the canonical `ErrorCode` enum value), red `error`
prefix, white message. If the server returned an `error_id`, append
`(error_id: ABCDEF12)` so the user can ask the operator about it.

## Secrets in output

Never print a full private key, full session key, or full server static
secret. When showing keys for "is this what I expect?" UX, print the
16-char fingerprint (`secure_llm_client.crypto.kdf.fingerprint`). Public
keys are fine to print in full (base64).

## Chat TUI

- Slash-commands: `/exit`, `/quit`, `/clear`. Anything else starting with
  `/` is reserved and prints `unknown command`.
- Inline streaming output uses `console.print(..., end="")`.
- Multi-line input: not in v1; one prompt per line.
- Footer hint shown once on entry: "Ctrl-D or /exit to quit, /clear to reset".

## Logging vs CLI output

CLI commands print human output to the console. They never print JSON log
lines. To stream server logs the user runs `make logs` or `sllm debug
logs`. CLI output goes to stdout; informational notices go to stderr.

## Internationalization

Not in v1. All strings are en-US.

## Adding new commands

1. Add the function to `client/secure_llm_client/cli/__main__.py`. Match
   the existing `--server` / `--insecure` flag pattern.
2. Document the command in `README.md` if it's user-facing.
3. If it touches `admin.*` endpoints, ensure the server side guards with
   `_require_admin` and the audit log records it.
