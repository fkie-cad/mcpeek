# Changelog

## 1.0.0 (2026-10-16)

First public release.

- Tool-call timeline in timestamp order across sessions: each `tool_use` is stitched to its `tool_result`, its session (the `sessionId` the records give; a transcript file name that differs is reported) and any sub-agent sidecar through the shared tool-use id, with nesting depth, denials and spawn rows.
- Inventory of configured MCP servers (user and project scope, with headers, `headersHelper` and the configured `oauth` object), MCP tools observed being called, permission grants (an allow rule with a wildcard in the server position, such as `mcp__*`, is listed as written with a note and not mapped to servers) and project `.mcp.json` server approvals, MCP OAuth client registrations (DCR or CIMD, token presence only) and spilled tool results (read from the CLI's spill stub). Project paths are mapped into the target root below HOME of the examined host, which is inferred or given with `--home`.
- Parsing of the per-server MCP logs and `--debug` files: connection attempts (with the remote server URL the log records, shown in `servers` and `timeline` with query values withheld by default), tool calls with logged duration and outcome (a call retried after session recovery is one call, marked as retried), elicitation and shutdown events, servers no longer configured, and a cross-check of the two logs. Log calls are joined to transcript calls and unmatched or ambiguous calls are listed as such.
- Log values that can be secrets are withheld by default (including error text and the text of records that match no known template) and listed with kind, size, SHA-256 prefix and source (`--show-sensitive` prints them). `--redact` masks credential-shaped configuration fields, server env and header values, credential-shaped command-line values and URL userinfo, query values and fragments.
- Symlinks that lead outside the target root are not followed and are reported; a second path to a file or folder that is already read is read once and reported. Malformed files are read as far as possible, with warnings that name the file and the field.
- Table and JSON output for every listing, plus a Markdown or HTML report.
- Artifact locations described in `mcpeek/data/claude_code.yml`, log formats in `docs/log-formats.md` (Claude Code CLI 2.1.226).
