# MCPeek

MCPeek is a read-only, offline forensic command-line tool for Model Context Protocol (MCP) activity recorded by
the Claude Code CLI. It rebuilds the MCP tool-call timeline from Claude Code CLI artifacts by stitching each call
to its result, session and sub-agent sidecar through the shared identifier (`id` and `tool_use_id` in the
transcript, `toolUseId` in the sub-agent metadata), and lists the servers, tools, grants and spilled results an
examiner then reads. It also parses the per-server MCP logs and `--debug` files the CLI writes and joins their
records to the transcript calls (through the `toolUseId` of `--debug` `[Stall] tool_dispatch_start` lines where
present, else by session, server, tool and time). MCPeek opens no network connections and does not modify the
artifacts it reads. It emits no attribution verdict: it reports what the artifacts contain and how records were
joined, and leaves the interpretation to the examiner.

## Installation

MCPeek needs Python 3.10 or newer (tested with 3.10 to 3.13). From a clone:

```bash
git clone https://github.com/fkie-cad/mcpeek
cd mcpeek
python3 -m venv .venv && .venv/bin/pip install .
.venv/bin/mcpeek --help
```

Or directly:

```bash
pip install git+https://github.com/fkie-cad/mcpeek
```

## Usage

```
mcpeek [GLOBAL OPTIONS] COMMAND [COMMAND OPTIONS]
```

MCPeek works on a **target root**: a home directory, or a copy of one, that contains `.claude.json` and
`.claude/` (what `~` was for the user on the examined host). Global options go before the command. The exit
status is 0 on success and 2 on a usage error (for example an unknown option, or a missing or nonexistent
target root).

| Global option | Meaning |
|---|---|
| `-t, --target DIR` | Target root. Required, must exist. |
| `--home PATH` | HOME on the examined host that the target root stands for, for example `/root` or `/home/alice` (see [Project paths and HOME](https://github.com/fkie-cad/mcpeek#project-paths-and-home)). Inferred if not given. |
| `--cache-dir DIR` | Additional cache folder holding `claude-cli-nodejs/` (for example a relocated `XDG_CACHE_HOME`), or that folder itself. Repeatable. A project or server folder inside a cache folder that is found anyway is read as part of that folder. |
| `--debug-file PATH` | Additional `--debug` file, or folder of them (for example from `claude --debug-file` or `CLAUDE_CODE_DEBUG_LOGS_DIR`). Repeatable. |
| `--session ID` | Only this session: the session id `sessions --quick` shows, the transcript file name (with or without `.jsonl`), or a prefix of at least 4 characters (see [Selecting sessions](https://github.com/fkie-cad/mcpeek#selecting-sessions)). Repeatable. |
| `--project P` | Only the sessions of this project: the encoded project folder name, the project path on the examined host, or a prefix of the folder name (see [Selecting sessions](https://github.com/fkie-cad/mcpeek#selecting-sessions)). Repeatable. |
| `--json` | Print JSON instead of tables. Not valid for `report`. JSON keeps values exact; tables, warnings and reports show control characters from the evidence as `\xNN` escapes. |
| `--redact` | Mask credential-shaped configuration values (see [Sensitive data](https://github.com/fkie-cad/mcpeek#sensitive-data)). |
| `--show-sensitive` | Print the log values that are withheld by default (see [Sensitive data](https://github.com/fkie-cad/mcpeek#sensitive-data)). Cannot be combined with `--redact`. |
| `--version` | Print the version and exit. |
| `-h, --help` | Print help. Every command has its own (`mcpeek timeline --help`). |

| Command | Output |
|---|---|
| `info` | Case overview: HOME used and how it was determined, counts, negotiated MCP protocol versions (when a `--debug` file records them), MCP log and debug-file summary, warnings. |
| `servers` | Configured MCP servers by scope (transport, command, args and env, or URL, headers and `headersHelper`, and the configured `oauth` object such as `clientId` and `callbackPort`; a configured `type` that is not a known transport, or `"type": null`, is shown as `unknown` with the value as written, `type_raw` in JSON; an entry with both `command` and `url` and no `type` shows both, labelled) with `--debug` file and MCP log details, plus servers seen only in the logs. A remote server URL recorded in the MCP log is shown as `(from MCP log)` when the server has no configured URL or the recorded URL differs from it (query values withheld by default). |
| `tools` | MCP tools observed being called, with transcript and MCP-log call counts. A log call joined to a transcript call counts under that call's server; other log calls in a folder shared by several server names count on a row for the folder, with the candidate names. |
| `sessions` | Session transcripts with cwd, time range and message, tool-call, MCP-call and sub-agent counts. `--quick` lists them without parsing them (see [Selecting sessions](https://github.com/fkie-cad/mcpeek#selecting-sessions)), `--limit N` keeps the N with the most recent activity. |
| `timeline` | Tool-call timeline across the main transcript and every sub-agent sidecar, in timestamp order across all sessions, with session, nesting depth, denials, spilled results, MCP log annotations and server events (a connect event names the remote server URL recorded in the MCP log). Log calls without a transcript call have no depth (the MCP log cannot tell delegated from direct calls). A call the CLI retried after session recovery (two `Calling` records linked by a `Retrying tool 'T' after session recovery` record) is one log call, marked `retried after session recovery`; the attempts are in its `notes` in JSON output. The default view shows MCP calls, sub-agent spawns, log calls without a unique transcript match and server events, and counts the other tools. `--all-tools` shows every call, `--mcp-only` only `mcp__*` calls (without server events), `--no-server-events` hides the server event rows (connect, shutdown, elicitation, ...). |
| `logs` | Per-file details of the MCP logs and `--debug` files, the cross-check between them, and the withheld sensitive values. `--records` lists every record, `--file TEXT` keeps only files whose path contains `TEXT`. |
| `credentials` | MCP OAuth client registrations: client id kind (DCR, CIMD or unknown), client id, issuer, redirect URI, and whether an access or refresh token is present. |
| `grants` | Permission grants (`permissions.allow`) from user- and project-scope `settings.local.json`, and project `.mcp.json` server approvals (`enabledMcpjsonServers`, `disabledMcpjsonServers`, `enableAllProjectMcpServers`) from those files and from `.claude.json` project entries, each with scope (`user` or the project path on the examined host) and source file. `mcp__<server>` and `mcp__<server>__*` are listed as MCP grants for every tool of that server (tool `*`). A rule with a wildcard in the server position (`mcp__*`, `mcp__a*__x`) is listed as written with no server and a note: the run-3, run-4 and run-8 experiments report `mcp__*` as skipped by CLI 2.1.226 ("Invalid permission rule"). |
| `report` | Overview, servers, MCP log calls, OAuth clients, sessions and warnings as one HTML (default) or Markdown (`--format md`) document. `-o, --output FILE` writes it to a file instead of stdout. The file's folder must exist. MCPeek does not write into the evidence: a path that resolves (symlinks followed) inside the target root, inside a `--cache-dir` folder, or inside or at a `--debug-file` path is refused with a usage error (exit 2) and nothing is written. |

Examples:

```bash
mcpeek -t /evidence/home/user info
mcpeek -t /evidence/home/user timeline --mcp-only
mcpeek --json -t /evidence/home/user timeline > timeline.json
mcpeek --cache-dir /evidence/xdg-cache --debug-file /evidence/debug.log -t /evidence/home/user logs
```

## Selecting sessions

A live home can hold hundreds of transcripts and many gigabytes. `sessions --quick` lists them in seconds without
parsing them: per `.claude/projects/<project>/<session>.jsonl` it reads the file size and mtime, the session id,
cwd and first timestamp from the first records, the last timestamp from the end of the file, and the number of
names in `<session>/subagents/` (`agent-*.meta.json`) and `<session>/tool-results/`, newest activity first. It
reads at most 8 MiB from each end of a transcript and skips lines over 1 MiB at the start, so cwd, first or last
can be `-`.
First and last come from the first and last records that carry a timestamp; `sessions` (without `--quick`) takes
the earliest and latest user and assistant record, so the two can differ by a moment.

Pick a session there and pass it to any command:

- `--session ID`: the session id `sessions --quick` shows, the transcript file name (with or without `.jsonl`), or
  a prefix of either (at least 4 characters).
- `--project P`: the encoded project folder name (`-home-alice-project`), the project path on the examined host
  (`/home/alice/project`, encoded as the CLI does: every character other than `A-Z`, `a-z`, `0-9` becomes `-`), or
  a prefix of the folder name.

Both are repeatable. An ambiguous value is a usage error (exit 2) that lists the candidates. A value that matches
nothing is a usage error too: for `--session` it points to `sessions --quick`, for `--project` it lists the project
folders.

```bash
mcpeek -t ~ sessions --quick --limit 10
mcpeek -t ~ --session 1b2c3d4e info
mcpeek -t ~ --session 1b2c3d4e timeline --mcp-only
mcpeek -t ~ --project ~/project sessions
```

What a filter keeps:

- **Transcripts:** only the selected ones are parsed, with their sub-agent and spilled-result folders. Of the
  others MCPeek reads the first records, for the session ids and HOME, and the last records when the first session
  id differs from the file name. When the first read finds no cwd record because it stopped at 8 MiB or skipped a
  line over 1 MiB, the transcript is read for its cwd as without a filter. Every transcript listed under a selected
  session id is selected, also a copy in another project folder.
- **MCP logs:** the files in which a selected session appears (the leading record that `--continue` writes counts
  with the session that follows it). In them, the calls of other sessions (after a `/clear` switch, for example)
  and their session-bound events are left out and counted per file, never shown as log-only; server process
  events (connect, shutdown, session switch) are kept. `logs` lists only the records of the selected sessions,
  records without a session id, and the withheld values in them. Values from other sessions' records stay
  withheld, also with `--show-sensitive`.
- **`--debug` files:** those named after a selected session or paired with its MCP-log records. To pair mirror
  lines exactly as an unfiltered run does, MCPeek also reads the log files of other sessions whose records or
  mirror lines lie within the pairing window (concurrent sessions). Their rows and records are not shown. `info`
  counts them, and `info --json`, `logs` and `report` name each of them with the calls, events and records of
  other sessions it holds.

The calls, joins, durations and cross-check of a selected session are those of an unfiltered run. `credentials`
and `grants` list the configuration in full, and so does `servers` for the configured servers. Its rows of servers
not in the current configuration and its MCP log details come from the log files shown, and each server gets its
calls in the selected sessions and the connection attempts in those files. `info` shows the filter and what it
left out. JSON output carries a `filter` object: list outputs become `{"filter": {...}, "<name>": [...]}`, and
`info` and `logs` get a `filter` key. The configuration views also carry `filter_applies` (`false` for
`credentials` and `grants`, `true` for `servers`) and `filter_note`, which says what is complete.

## Supported artifacts

MCPeek was built and tested against **Claude Code CLI 2.1.226** on Linux. The locations are declared in
`mcpeek/data/claude_code.yml`, the log message templates in `mcpeek/data/claude_code_log_messages.yml`. Paths
are relative to the target root.

| Location | What MCPeek reads | Notes |
|---|---|---|
| `.claude.json` | `mcpServers` (user scope and per project, with each server's `oauth` object), the `projects` map, project `.mcp.json` approvals | Project paths are mapped into the target root to find project files (see below). |
| `.claude/backups/.claude.json.backup.*` | Server names | Used as candidate names for MCP-log folders. |
| `.claude/.credentials.json` | `mcpOAuth` client registrations | Token values are never output. |
| `.claude/settings.local.json`, `<project>/.claude/settings.local.json` | `permissions.allow`, `enabledMcpjsonServers`, `disabledMcpjsonServers`, `enableAllProjectMcpServers` | |
| `<project>/.mcp.json` | Project-scope server definitions | Looked up at the project root only, never recursively. |
| `.claude/projects/<project>/<session>.jsonl` | `tool_use` and `tool_result` records, denials, cwd, timestamps, CLI version | The session id is the records' `sessionId`. A file name that differs from it (a renamed copy) or several ids in one file are reported in a warning; the companion `<session>/` folder is found by the file name. |
| `.claude/projects/<project>/<session>/subagents/agent-<id>.jsonl` and `.meta.json` | Sub-agent calls, spawning `toolUseId`, nesting depth | Linked by id, never by tool name. |
| `.claude/projects/<project>/<session>/tool-results/*.txt` | Spilled tool results | Resolved path per call: a `spilled:` note in the `timeline` Source column, `spill_path` in JSON output. Only the stub the CLI writes in place of a spilled result is read as a reference ("... exceeds maximum allowed tokens. Output has been saved to ..." or "Output too large ... Full output saved to: ..."), not a path inside a tool's own result such as a `Read` of a `tool-results` file. |
| `.claude/debug/*.txt`, `.claude/debug/latest` | `--debug` files | `latest` is reported, never followed. |
| `.cache/claude-cli-nodejs/`, `Library/Caches/claude-cli-nodejs/`, `AppData/Local/claude-cli-nodejs/Cache/` | Per-server MCP logs | `claude-cli-nodejs/` and `*/claude-cli-nodejs/` directly below the target root are also searched. |

The macOS and Windows MCP-log locations, the rotated debug file (`<sessionId>.1.txt`) and `sdk-*.txt` debug files
are taken from the 2.1.226 bundle and were not observed on disk.

MCPeek follows a symlink in the target only if it resolves inside the target root (or inside a folder given with
`--cache-dir` or `--debug-file`). Any other symlink on a path MCPeek looks up, and any symlink in a debug folder
whatever its name, is not followed and is listed with its link text in the warnings and in `logs`.
`.claude/debug/latest` is never followed. A path that leads to a file or folder MCPeek
already reads under another path (for example a symlinked second name for a project folder) is read once and
listed as an alias. A spilled-result reference that resolves outside the target root is reported, not opened.

Malformed files are read as far as possible: invalid UTF-8 is decoded with replacement characters, and a file or
field of an unexpected JSON type is skipped or coerced with a warning that names the file and the field.

### Project paths and HOME

Project paths in `.claude.json` and the `cwd` values of transcripts are absolute paths on the examined host, for
example `/root/pi`. The target root stands for that host's HOME, so the project's own `.claude/settings.local.json`
and `.mcp.json` are looked up at `<target>/<project path relative to HOME>` (`<target>/pi` for HOME `/root`).
HOME is taken from `--home` or inferred: the ancestor of the project paths under which the most project folders
exist in the target (ties: more path components matched, then alphabetical order), else the conventional home
(`/root`, `/home/<user>`, `/Users/<user>`, `C:\Users\<user>`) of the project paths, else their common parent
folder. `info` shows the HOME used and how it was determined, with a tie or the runner-up candidate. A tie, a
runner-up, an inferred HOME that is not a conventional home location, or a HOME taken from the common parent
folder is also reported as a warning that suggests `--home`. A project path outside HOME is reported as a
warning. For a project at HOME itself the project file is the user-scope `.claude/settings.local.json`. Its grants
are listed once, with scope `user + project <path>`.

### MCP logs and `--debug` files

MCPeek also reads the two logs Claude Code CLI writes about MCP activity (format reference:
[`docs/log-formats.md`](https://github.com/fkie-cad/mcpeek/blob/main/docs/log-formats.md), CLI 2.1.226):

- **Per-server MCP log** `~/.cache/claude-cli-nodejs/<project>/mcp-logs-<server>/<start>.jsonl` (also
  `$XDG_CACHE_HOME`, macOS `~/Library/Caches`, Windows `%LOCALAPPDATA%\claude-cli-nodejs\Cache`), written by every
  CLI run that connects a server, with or without `--debug`.
- **`--debug` file** `~/.claude/debug/<sessionId>.txt` (also `.1.txt` and `sdk-*.txt`), written only in debug
  mode.

From them MCPeek recovers connection attempts (transport, remote server URL, connect time, `serverVersion`,
failures), tool calls with logged duration and outcome, elicitation, shutdowns, and servers no longer configured.
Each log call is joined to its transcript `tool_use`: by the `toolUseId` of the `[Stall] tool_dispatch_start` line
when a `--debug` file has one, otherwise by session, server, tool and time. Log calls without a transcript call
(log-only), log calls that fit several transcript calls (ambiguous) and transcript calls without a log record are
listed as such, every row with its source file. MCPeek reports the join method and time offsets but does not
interpret an offset or a missing record.

## Sensitive data

- **Configuration values are shown as stored by default**: MCP server command lines, env values, header values
  and `headersHelper` commands, configured server URLs, the configured `oauth` object of a server (`clientId`,
  `callbackPort`, ...), OAuth server URLs, client ids, issuers and redirect URIs,
  and (in JSON output) short summaries of tool-call inputs and results from the transcripts. `--redact` masks the
  values of credential-shaped keys (`accessToken`, `refreshToken`, `idToken`, `clientSecret` and their snake_case
  forms), every MCP server env and header value (names are kept), credential-shaped values in stdio command lines
  and `headersHelper` commands (the value after `=` or `:` following a name that contains `token`, `key`,
  `secret`, `password`, `passwd`, `auth` or `credential`, the argument after a flag with such a name, the value
  after an authorization scheme word such as `Bearer`, `Basic`, `Digest` or `token`, in the same argument or as
  the next one, and well-known token formats such as `ghp_...`, `sk-...`, `AKIA...` or JWTs), and the userinfo,
  query values and fragment of every value that is a URL. It does not change the transcript summaries
  (`input_summary`, `result_summary`), which can contain tool arguments, tool error text and elicitation answers.
- **Log values that can be secrets or personal data are withheld by default.** This covers values from the MCP
  logs and `--debug` files such as connect-time stderr, HTTP header values, URL userinfo, query values and
  fragments, tool error text, the error text of connection and transport errors (the whole text of an error
  record whose template is not known to hold only fixed text), the text of every record that matches no known
  template, elicitation questions, schemas and answers (the schema's property names included), proxy settings and permission rules. Template fields
  that are not free text (outcomes, durations, codes, transports, tool names) stay visible. The output shows
  `[withheld:<kind>:<size>B]`, and `logs` lists each withheld value with kind, size, a 12-character SHA-256 prefix
  and its source file and line; size and hash cover exactly the bytes that `--show-sensitive` prints for the
  value. A hash prefix of a short or guessable value can be reversed by trying candidates, so treat it as
  sensitive when sharing output.
- **OAuth token values** from `.credentials.json` are never output. `credentials` only says whether a token is
  present. Inside `discoveryState`, whatever the options, every URL keeps only scheme, host and path (its
  userinfo, query values and fragment are replaced by `[REDACTED]`), and the value of every key whose name contains
  `key`, `auth`, `credential`, `assertion`, `cookie`, `session`, `private`, `bearer`, `password`, `passwd`,
  `secret`, `token` or `verifier` (case, `_` and `-` ignored) is replaced by `[REDACTED]` unless it is null, a
  boolean, a URL or a list of URLs. Such a key whose name ends in `endpoint`, `uri`, `url`, `urls`, `supported`,
  `metadata` or `servers` (metadata, for example `token_endpoint` or `authorizationServerMetadata`) is walked
  into instead.

## Scope and limitations

- MCPeek covers the Claude Code CLI only. Formats and locations follow CLI 2.1.226 on Linux, other versions may
  differ, and the locations listed above as taken from the bundle are not verified on disk.
- Transcripts, credentials, grants and the default debug folder are read from `<target>/.claude/` only. A
  relocated `CLAUDE_CONFIG_DIR` is not searched for transcripts (a relocated debug folder can be added with
  `--debug-file`). A `projects` folder or a `.claude.json` in another `.claude*` folder directly below the target
  root (for example `<target>/.claude-work/.claude.json`) is named in a warning and not read.
- Project-scope `settings.local.json` and `.mcp.json` files are found only for project paths below HOME of the
  examined host whose folders are part of the target root.
- Under `--session` or `--project`, a server name that only the transcripts or `--debug` files of other sessions
  record is not a candidate name for an MCP-log folder. A transcript whose file name is not one of its session ids
  and whose first and last records both give ids other than its most frequent one is listed by `sessions` under
  that most frequent id, which `--session` does not match (its other ids and its file name do).
- MCPeek does not recover tool descriptions or input schemas, read network captures, or verify the integrity of
  the artifacts (transcripts are not authenticated). A missing record is reported, not treated as proof that
  something did not happen.
- MCPeek emits no attribution verdict. It does not classify activity or infer intent or actor. The examiner reads
  that context from the transcripts the timeline points to.

## Citation

MCPeek was released with the paper "When AI Takes Action: MCP Forensics from Evidence to Attribution" (NordSec
2026). If you use it, please cite:

```bibtex
@inproceedings{hilgert2026mcpforensics,
  author    = {Hilgert, Jan-Niclas and K{\"u}lper, Michael and Lambertz, Martin and Gruber, Jan},
  title     = {When {AI} Takes Action: {MCP} Forensics from Evidence to Attribution},
  booktitle = {Secure IT Systems (NordSec 2026)},
  series    = {Lecture Notes in Computer Science},
  publisher = {Springer},
  year      = {2026}
}
```

Volume, pages and DOI will be added after publication.

## Data availability

The experimental data behind the paper is not published because it contains credentials and account data
(for example OAuth tokens). It is available from the authors on request.

## License

MIT, Copyright (c) 2026 Fraunhofer FKIE. See [LICENSE](https://github.com/fkie-cad/mcpeek/blob/main/LICENSE).
