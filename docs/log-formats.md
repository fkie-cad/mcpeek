# Claude Code CLI log formats: per-server MCP log and `--debug` file

Reference for **Claude Code CLI 2.1.226** (Linux x64 build). It describes the two plain-text logs
the CLI writes about MCP activity, precisely enough to write a parser, and how MCPeek reads them.
Other versions may differ.

Status markers used throughout:

- **obs**: observed in files written by 2.1.226.
- **static**: read from the 2.1.226 bundle (JavaScript inside the binary), not observed on disk.

Placeholders: `/root/proj-a` (a project directory), `probe` (a server name).
`enc(x)` is the CLI's path sanitizer (section 2.3).

---

## 1. The two logs at a glance

| | Per-server MCP log | `--debug` session file |
|---|---|---|
| Path (Linux default) | `~/.cache/claude-cli-nodejs/<enc(cwd)>/mcp-logs-<enc(server)>/<start>.jsonl` | `~/.claude/debug/<sessionId>.txt` |
| Enabled | always (no flag, env var or setting turns it off) | only in debug mode (3.1) |
| Granularity | one file per CLI process and server folder | one file per session id (at write time), shared by processes |
| Format | JSON Lines, two record shapes | text lines `<ISO> [LEVEL] <message>` |
| Server name | sanitized, only in the folder name | raw, in each mirrored line |
| Content | MCP client events only | everything the CLI logs, MCP events mirrored |
| Write path | buffered, flushed every 1 s or at 50 records | one append per line |
| Lost on SIGKILL | up to the last ~1 s of records, or the whole file | in-flight appends only (static) |
| Retention | file name date older than `cleanupPeriodDays`, current cwd only | file mtime older than `cleanupPeriodDays`, whole folder |
| Redaction | only header names ending in `authorization` | keyword-based `[REDACTED]` (3.5) plus the same header rule |
| Follows `CLAUDE_CONFIG_DIR` | no | yes |
| Follows `XDG_CACHE_HOME` | yes (Linux) | no |

---

## 2. Per-server MCP log

### 2.1 Production

| Item | Behaviour | Status |
|---|---|---|
| Writer | The CLI process itself, never the MCP server. Sub-agents run in the same process and write to the same file. | obs |
| Enablement | Written with and without `--debug`. Telemetry and error-reporting opt-outs (`DISABLE_TELEMETRY`, `DISABLE_ERROR_REPORTING`, `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`, ...) do not affect it. | obs |
| Commands that write | Anything that connects or tries to connect a server: headless `-p`, the interactive TUI, `claude mcp list`, `claude mcp get` (each a full connect and shutdown), `--mcp-config` (with or without `--strict-mcp-config`), failed connects. A `-p` run without any tool call still writes the connect and shutdown records. | obs |
| Commands that do not write | `claude mcp add` / `remove`, `--bare` (no MCP config loaded), no server configured. | obs |
| File name | `new Date().toISOString()` with `:` and `.` replaced by `-`, evaluated once when the module loads (process start), shared by all servers of the process: `2026-10-16T12-56-56-665Z.jsonl`. Always UTC, millisecond precision. | obs (format), static (origin) |
| File creation | By the first flush of the buffered writer (`appendFile`; on error `mkdir -p` the folder and retry), not at process start. A process that never logs for a server, or dies before the first flush, leaves no file. | obs |
| Name vs. records | The first record is always later than the file name time: about 50 ms to 1 s in normal runs, longer when an interactive trust or project-scope approval dialog is open before connecting (observed maximum 63.3 s). | obs |
| Buffering | Per-file writer, flush interval 1000 ms (timer starts with the first record into an empty buffer), immediate flush at 50 buffered records, flush on graceful exit. One flush = one append of whole lines. | static, consistent with obs |
| mtime | 0 to ~1 s after the last record's timestamp (time of the last flush). | obs |
| SIGKILL | Records younger than the last flush are lost: a `Calling MCP tool` record can be missing although the transcript has the `tool_use`, a call can lack its completion, shutdown records are absent, or no file exists at all. A truncated last line was not observed (each flush appends complete lines) but must be tolerated. | obs |
| Write failure | If the folder cannot be created or written (for example a path component is a regular file: `ENOTDIR`), the batch is dropped silently. The only trace is a debug-file line `Dropping log batch for <path>: <error>` when debug mode is on. `chmod 555` does not stop a root process. | obs |
| Pre-sink records | Records emitted before the log sink is initialized are queued and replayed. Timestamp, `sessionId` and `cwd` are taken at replay time. | static |
| Permissions | Files `0644`, folders `0755` under a `022` umask. | obs |
| Concurrent processes | Each process has its own file name (start time). Two processes started in the same millisecond in the same cwd would append to the same file. | obs (distinct names), static (same-ms case) |

### 2.2 Location

`<cacheRoot>/claude-cli-nodejs/<enc(cwd)>/mcp-logs-<enc(server)>/<start>.jsonl`

| OS | `cacheRoot` | Status |
|---|---|---|
| Linux | `$XDG_CACHE_HOME` if set, else `$HOME/.cache` | obs (both) |
| macOS | `$HOME/Library/Caches` (`XDG_CACHE_HOME` ignored) | static |
| Windows | `%LOCALAPPDATA%` (fallback `%USERPROFILE%\AppData\Local`), then `claude-cli-nodejs\Cache\` (note the extra `Cache` level) | static |

- `CLAUDE_CONFIG_DIR` does **not** move the MCP log (it moves `.claude/`, transcripts and the debug folder). obs
- `cwd` is `process.cwd()` at write time; it equals the record's `cwd` field and the launch directory. The Bash tool's `cd` does not change it. obs

### 2.3 Name sanitization and collisions

```
enc(s) = s.replace(/[^a-zA-Z0-9]/g, "-")
if len(enc(s)) > 200: enc(s)[:200] + "-" + base36(abs(h(s)))     # static
h(s) = 32-bit Java-style string hash over the original s: h = (h << 5) - h + charCode, | 0
```

| Item | Behaviour | Status |
|---|---|---|
| cwd folder | `/root/proj-a` becomes `-root-proj-a`. Same encoder as `~/.claude/projects/<enc(cwd)>/`. Windows `C:\x\y` becomes `C--x-y`. | obs (Linux), static (Windows) |
| server folder | `probe_x` becomes `mcp-logs-probe-x`. `.` and spaces become `-`. | obs (`_`, `-`), static (`.`, long names) |
| Collisions | `a_b`, `a-b`, `a.b`, `a b` all map to `mcp-logs-a-b`. Servers whose names collide share **one file per process, interleaved**; records carry no server field, so the file alone cannot tell them apart. | obs |
| Reversing | Not possible. Candidate raw names come from the configuration (`.claude.json`, its backups, `.mcp.json`), from debug lines `MCP server "<raw>"`, and from transcript tool names `mcp__<server>__<tool>` (the transcript replaces `[^a-zA-Z0-9_-]` with `_`, so `enc` of it equals the folder suffix). | |

### 2.4 Retention

| Item | Behaviour | Status |
|---|---|---|
| What is deleted | Files in `<cacheRoot>/claude-cli-nodejs/<enc(current cwd)>/mcp-logs-*/` whose **file name** parses to a date older than `now - cleanupPeriodDays` (default 30). mtime is ignored. Names that do not parse are kept. Empty `mcp-logs-*` folders are removed. | obs |
| Scope | Only the folder of the cwd the CLI is running in. Other projects' logs are swept only when the CLI next runs there; logs of abandoned projects persist. | obs |
| When | Headless: 5 s after MCP connect, only if the process lives that long. Interactive: 5 s after the first submitted prompt, deferred in 10-minute steps while the user was active in the last 60 s. A `~/.claude/.last-cleanup` younger than 24 h defers the sweep once by 10 minutes. `--bare` skips it. | obs, static (timers) |
| `cleanupPeriodDays: 0` | Fails schema validation (minimum 1): the whole settings file is ignored and the sweep is skipped. | obs |
| Consequence | A gap in file names is not evidence of inactivity if a sweep may have run (check `.last-cleanup`). | |

### 2.5 Record layout

UTF-8, one JSON object per line, LF terminator, no BOM, no header. Exactly two shapes, fixed key order:

```
{"debug":"<message>","timestamp":"<ISO>","sessionId":"<uuid>","cwd":"<absolute path>"}
{"error":"<message>","timestamp":"<ISO>","sessionId":"<uuid>","cwd":"<absolute path>"}
```

| Key | Meaning | Status |
|---|---|---|
| `debug` | message from the client's debug channel; always a string | obs |
| `error` | message from the error channel: for an `Error` object its `stack` (multi-line, `    at ...` frames), else the message text | obs |
| `timestamp` | `new Date().toISOString()` at record creation (not at flush): `YYYY-MM-DDTHH:MM:SS.mmmZ`, UTC, 24 characters. Non-decreasing within a file; equal values are common. | obs |
| `sessionId` | the CLI's current session id at record time (it can change mid-file, 4.2) | obs |
| `cwd` | `process.cwd()` at record time | obs |
| no other keys | No server name, level, tool-use id, agent id or arguments exist in code or data. | obs, static |

Messages that embed JSON (`capabilities`, `HTTP transport options`, `Environment`, elicitation) are JSON text inside the JSON
string: decode the record, then decode the suffix. Multi-line messages occur (stderr, stacks, tool error text); use DOTALL regexes.
The writer never truncates: connect-time stderr is accumulated up to 64 MiB and logged as one record (static). Do not assume
a line length limit.

### 2.6 Timestamps and durations

| Text | Unit and rounding | Status |
|---|---|---|
| `Tool 'T' completed successfully in N` | `M < 1000`: `"{M}ms"`; `M < 60000`: `"{floor(M/1000)}s"`; else `"{floor(M/60000)}m {floor((M%60000)/1000)}s"`. Floor, never rounded: `3s` means 3000 <= M < 4000. | obs (`ms`, `s`), static (`Nm Ss`) |
| `Tool 'T' failed after Ns: <error>` | always whole seconds, floored: `failed after 0s` for sub-second failures | obs |
| `Tool 'T' still running (Ns elapsed)` | every 30 s from the call start: 30, 60, 90, ... | obs |
| `Successfully connected (transport: X) in Nms`, `Connection failed after Nms` | integer ms | obs |
| `... connection closed after Ns (...)`, `... connection dropped after Ns uptime` | whole seconds since connect, floored | obs |

For a duration logged in `ms`, the completion record's timestamp minus the `Calling` record's timestamp, minus the logged duration, is -2 to +1 ms (obs).

### 2.7 Message catalog

Regexes are Python `re` on the decoded message (`k` = record key). **S** marks messages that can carry secrets or
personal data in clear (2.8). All observed records matched exactly one row of 2.7.1 to 2.7.5; the bundle has about 360
distinct templates, two near-identical copies of the MCP client module, and the static rows below summarize the rest.

#### 2.7.1 Connection lifecycle

| Kind | k | Template / regex | Extracted | Status |
|---|---|---|---|---|
| start | debug | `^Starting connection with timeout of (\d+)ms$` | timeout (`MCP_TIMEOUT`, default 30000) | obs |
| stderr | **error** | `^Server stderr: ([\s\S]*)$` | stdio server stderr written **before or while connecting**, verbatim incl. trailing newline. Logged when the connection attempt ends, as the record directly before the outcome record (`connected` or `failed`, 228 of 228 observed); its timestamp equals the outcome's (197) or is 1 ms (29) or 2 ms (2) earlier, never later. The timestamp is that of the connect outcome, not when the server wrote the text. The listener is removed after connect: call-time stderr is never logged. HTTP servers' stderr never reaches the client. **S** | obs |
| probe stderr | debug | `^Probe-closed server stderr: ([\s\S]*)$` (version-negotiation probe path; same content class as stderr, but a **debug** record). **S** | static |
| probe | debug | `version negotiation probe closed the stdio server ...`, `version negotiation probe failed on the <t> transport; reconnecting pinned legacy` | | static |
| connected | debug | `^Successfully connected \(transport: ([^)]+)\) in (\d+)ms$` | transport = configured `type` or `stdio` (`stdio`, `http`, `sse`, `ws`, `sse-ide`, `ws-ide`, `claudeai-proxy`, ...), connect ms | obs (`stdio`, `http`) |
| capabilities | debug | `^Connection established with capabilities: (\{[\s\S]*\})$` | JSON `{hasTools, hasPrompts, hasResources, hasResourceSubscribe, serverVersion}`. `serverVersion` is the server's self-reported `serverInfo` object (`name`, `version`, possibly more fields) or the string `"unknown"`. The other module copy (runtime arm `v2`) adds `protocolEra` and `negotiatedProtocolVersion`. Accept extra keys. | obs (v1 shape), obs in debug files (v2 shape) |
| failed (debug) | debug | `^Connection failed after (\d+)ms(?: \(([^)]*)\))?: ([\s\S]*)$` | ms, code (`-32000`, `ConnectionRefused`, `ENOENT`, `404`, ...), message (may contain a URL) | obs |
| failed (error) | **error** | `^Connection failed(?: \(([^)]*)\))?: ([\s\S]*)$`, twin of the debug record, directly after it, same ms or 1 ms later (12 and 1 of 13 observed) | | obs |
| error object | **error** | `^([A-Za-z]*Error)(?:: ([^\n]*))?\n\s+at [\s\S]*$` (JS stack with `/$bunfs/root/...` frames) | | obs |
| timeout | debug | `^Connection timeout triggered after (\d+)ms \(limit: (\d+)ms\)$` | | static |
| retry | debug / error | `Transient <code> on initial connect — retry j/3 in Nms`, error `Initial-connect retry j threw: <msg>` | | obs (`Transient`, in debug files), static (`threw`) |
| skipped | debug | `Skipping connection (blocked by managed policy)`, `Skipping connection (cached needs-auth)` | | static |
| config error | debug / error | `'url' is not a valid URL. ...`, `No URL configured for this server` | | static |
| stdout overflow | error | `stdout overflow` / `http body overflow` messages, `Ignoring non-JSON line on stdout: <line>` | server text | static |
| channels | debug | `^Channel notifications skipped: (.*)$` (reason observed: `server did not declare claude/channel capability`) | **interactive TUI marker**, re-emitted on every (re)connect and after `/clear` | obs |
| channels | debug | `Channel notifications registered`, `... re-registered after reconnect`, `notifications/claude/channel: <first 80 chars>` (**S**), `notifications/claude/channel/permission: <id> -> <behavior> (...)` | | static |

#### 2.7.2 HTTP, SSE, WebSocket, proxy transports

| Kind | k | Template / regex | Extracted | Status |
|---|---|---|---|---|
| http init | debug | `^Initializing HTTP transport to (\S+)$` | full URL incl. query. **S** | obs |
| node | debug | `^Node version: (\S+), Platform: (\S+)$` | runtime version | obs |
| env | debug | `^Environment: (\{.*\})$` | `NODE_OPTIONS`, `UV_THREADPOOL_SIZE`, `HTTP_PROXY`, `HTTPS_PROXY` (userinfo, query and fragment stripped), `NO_PROXY` (verbatim); `"not set"` / `"default"` otherwise | obs |
| options | debug | `^HTTP transport options: (\{.*\})$` | `{url, headers, hasAuthProvider, timeoutMs}`. `headers` = `User-Agent`, `Accept-Encoding`, then every configured header **after `${ENV}` expansion** plus `headersHelper` output. Only header names whose lower-case form ends with `authorization` are replaced by `"[REDACTED]"`. `hasAuthProvider` is false when the user configured an `Authorization` header. **S** | obs |
| created | debug | `^HTTP transport created successfully$`, `^Client created, setting up request handler$` | | obs |
| testing | debug | `^Testing basic HTTP connectivity to (\S+)$` (log line only, no probe request) | URL. **S** | obs |
| parsed | debug | `^Parsed URL: host=([^,]*), port=([^,]*), protocol=(\S+)$` | host, port (`default` if absent), scheme | obs |
| loopback | debug | `^Using loopback address: (\S+)$` | | obs |
| http failed | debug | `^HTTP Connection failed after (\d+)ms: ([\s\S]*) \(code: ([^,]*), errno: ([^)]*)\)$`, followed by an error-object record and the failed pair | | obs |
| no token | debug | `^No token data found$`: logged on **every HTTP request** when an OAuth provider is attached and no token is stored | per-request counter | obs |
| dropped | debug | `^([A-Z-]+) connection dropped after (\d+)s uptime$` | | obs |
| conn error | debug | `^Connection error: ([\s\S]*)$`; errno-specific variants without the prefix: `Connection reset - server may have crashed or restarted`, `Connection timeout - ...`, `Connection refused - ...`, `Broken pipe - ...`, `Host unreachable - ...`, `Process not found - ...`, `Failed to spawn process - ...` | | obs (prefix form), static (variants) |
| terminal | debug | `^Terminal connection error (\d+)/(\d+)$` (normal at every HTTP shutdown: `1/3`) | | obs |
| session | debug | `MCP session expired (server no longer recognizes session ID), triggering reconnection`, `SSE GET-stream reconnection exhausted; ...` (observed: `...; leaving transport up (POST still works)`), `Closing transport (<reason>)` (observed: `session expired`), `Error during close: <msg>` | | obs (all but `Error during close`, which is static) |
| SSE | debug | `SSE transport initialized, awaiting connection` (no headers line for SSE), `SSE Connection failed after Nms: {"url",...}` (**S**), `Setting up SSE-IDE transport to <url>` | | static |
| WebSocket | debug | `Initializing WebSocket transport to <url>`, `WebSocket transport options: {"url","headers","hasSessionAuth"}` (same header rule, **S**) | | static |
| claude.ai proxy | debug | `Initializing claude.ai proxy transport for server <id>`, `Using claude.ai proxy at <url>`, `claude.ai proxy transport created successfully`, `claude.ai proxy connection failed after Nms: <msg>`, `Stateless claudeai-proxy ...`, `tools/list 401/403 on claude.ai proxy ...` | connector id | obs (first four, in debug files), static (rest) |
| headers helper | debug / error | `Executing headersHelper to get dynamic headers`, `Successfully retrieved N headers from headersHelper`, `Error getting headers from headersHelper: <msg>`, `Header values reference unset environment variables: <names>` | | static |

#### 2.7.3 Tool calls

| Kind | k | Template / regex | Extracted | Status |
|---|---|---|---|---|
| call | debug | `^Calling MCP tool: (.*)$` | raw tool name as defined by the server. No arguments, no tool-use id, no agent id. | obs |
| done | debug | `^Tool '(.*?)' completed successfully in (\d+ms\|\d+s\|\d+m \d+s)$` | duration (2.6) | obs |
| heartbeat | debug | `^Tool '(.*?)' still running \((\d+)s elapsed\)$` | | obs |
| failed | debug | `^Tool '(.*?)' failed after (\d+)s: ([\s\S]*)$` | whole seconds, error text (**S**). Also written for a call still in flight when the CLI shuts down gracefully, inside the shutdown records and without an error-text record before it: `MCP error -32001: AbortError: shutdown` (headless run ended by SIGTERM, between the first `Sending SIGINT` and the rest of the shutdown sequence) and `MCP error -32000: Connection closed` (interactive `/exit` while the call waited for an elicitation, after SIGINT, SIGTERM and `Elicitation response: {"action":"cancel"}`). In the observed runs only a call cut off by SIGKILL ended without a completion record (2.1). | obs |
| error text | **error** | no prefix: the `isError` result's text items joined by `\n` (`[Resource link: <name>] <uri> (<desc>)` for links, `Unknown error` if none). Immediately (<= 1 ms) followed by `failed after` repeating the same text. The text is server-defined and can look like any other error record (an error stack, `Connection failed: ...`), so detect it by the following `failed after` record with the same text, not by its own form. **S** | obs |
| abort | debug | `Tool 'T' aborting: no response or progress notification for Ns (idle timeout Ms)`, `Tool 'T' aborting: transport error Ns ago, response presumed lost` | | static |
| session recovery | debug | `^MCP session expired during tool call \(([^)]*)\), clearing connection cache for re-initialization$` (observed reason: `connection closed`), `^Retrying tool '(.*?)' after session recovery$` | reason; tool | obs |
| auth retry | debug | `Tool 'T' returned <status>; ... retrying once`, `Tool 'T' rejected the session credential (...)`, `Tool call returned 401 Unauthorized - token may have expired` | | static |
| other | debug / error | `Tool 'T' returned -32003 needs_approval (...)`, `Normalized input schema for tool "T" ...`, `Skipping tool "T": <reason>. ...`, `Tool "T" input schema would be rejected ...`, error `MCP server "S" tool "T": unexpected response format` | | static |

**Retry after session recovery (obs).** When the server no longer knows the MCP session (for example after it was
restarted during an interactive session), the CLI reconnects and calls the tool a second time inside the same tool use.
At most one retry is made. The transcript has one `tool_use` and one `tool_result`; the MCP log has two `Calling`
records. Observed sequence (MCP log of `mcplogs-rugpull` `int-MS-T0T0`, `-T0T2`, `-T0T4`, and the debug mirror lines of
run-8), 40 to 207 ms from the first `Calling` record to `reconnection successful`:

1. `Calling MCP tool: T`
2. `HTTP connection dropped after Ns uptime`, `Connection error: ... Error POSTing to endpoint: ...` (the server's "Session not found" reply; observed with a `Streamable HTTP error: ` prefix in the `mcplogs-rugpull` runs and without it in run-8), `MCP session expired (server no longer recognizes session ID), triggering reconnection`, `Closing transport (session expired)`, `HTTP transport closed/disconnected, attempting automatic reconnection`
3. `Tool 'T' failed after 0s: <error>` (observed: `MCP error -32000: Connection closed` in the `mcplogs-rugpull` runs, `Connection closed` in run-8), then `MCP session expired during tool call (connection closed), clearing connection cache for re-initialization`
4. a new connect sequence (`Initializing HTTP transport ...` to `Connection established with capabilities`), with `Retrying tool 'T' after session recovery` written while it runs
5. `Calling MCP tool: T`, then `Tool 'T' completed successfully in Nms` (or `failed after`), then `HTTP reconnection successful after Nms (attempt 1)`

In a debug file, `[Stall] tool_dispatch_start` precedes the first `Calling` line and `[Stall] tool_dispatch_end ...
outcome=ok` follows the retry's completion; both carry the same `toolUseId`, and no second `tool_dispatch_start` is
written for the retry. Before the next call, an SSE GET-stream drop after the restart typically leaves `connection
dropped`, `Connection error: ... Failed to open SSE stream: Not Found` and `SSE GET-stream reconnection exhausted;
leaving transport up (POST still works)` records. How MCPeek reports the two attempts is described in section 5.

#### 2.7.4 Elicitation and roots

| Kind | k | Template / regex | Extracted | Status |
|---|---|---|---|---|
| request | debug | `^Received elicitation request: (\{[\s\S]*\})$` | full JSON-RPC request (`message`, `requestedSchema`). **S** | obs |
| request (print mode) | debug | `^Elicitation request received in print mode: (\{[\s\S]*\})$`; headless runs cancel automatically, no response record | **S** | obs |
| response | debug | `^Elicitation response: (\{[\s\S]*\})$` | `{"action":"accept","content":{...}}` with the **user's answers in clear**, or `{"action":"decline"}` / `{"action":"cancel"}`. **S** | obs |
| other | debug / error | hook resolution, completion notifications, URL elicitation (`Tool 'T' requires URL elicitation (error -32042 ...)`, `User accepted\|declined\|cancelled URL elicitation <id>`), `Elicitation error: <e>` | | static |
| roots | debug | `^Received ListRoots request from server$` (between `Calling` and completion when requested during a call) | | obs |

#### 2.7.5 Shutdown and process control

| Kind | k | Template / regex | Status |
|---|---|---|---|
| SIGINT | debug | `^Sending SIGINT to MCP server process$` (stdio only) | obs |
| SIGTERM | debug | `^SIGINT failed, sending SIGTERM to MCP server process$` (process still alive 100 ms after SIGINT) | obs |
| SIGKILL | debug | `^SIGTERM failed, sending SIGKILL to MCP server process$` | static |
| exited | debug | `^MCP server process exited cleanly$` (pid gone; also printed after SIGTERM, so "cleanly" does not mean graceful) | obs |
| closed | debug | `^([A-Z-]+) connection closed after (\d+)s \((cleanly\|with errors)\)$`; transport is the configured `type` upper-cased, `UNKNOWN` for a `--mcp-config` entry without `type` (while `connected` says `stdio`) | obs |
| cache cleared | debug | `^Cleared connection cache for reconnection$` (follows `closed`; not a reconnect) | obs |
| errors | debug | `Cleanup timeout reached, stopping process monitoring`, `Error sending SIGINT\|SIGTERM\|SIGKILL: <e>`, `Error terminating process: <e>`, `Error closing client: <e>` | static |
| reconnect | debug / error | `<T> transport closed/disconnected, attempting automatic reconnection`, `Scheduling reconnection attempt n in Nms`, `<T> reconnection successful after Nms (attempt n)`, `Max reconnection attempts (5) reached, giving up`, `<T> reconnection attempt n failed after Nms: <e>`, `Server is disabled, skipping automatic reconnection`, `Error during reconnection: <e>` | obs (`transport closed/disconnected`, `reconnection successful`; observed after a session expiry, 2.7.3), static (rest) |

A user-initiated `/mcp` reconnect or disable/enable leaves only an ordinary shutdown sequence followed by a new connect
sequence, with no marker (obs).

#### 2.7.6 Lists, resources, prompts, OAuth (mostly static)

| Kind | Templates | Status |
|---|---|---|
| list_changed | `Received tools\|prompts\|resources/list_changed notification, refreshing ...`, `Synthesized ... refetch after listen-stream reopen ...`, `tools/list failed after list_changed — keeping previous tool set`, error `Failed to refresh <x> after list_changed notification: <e>`. Emitted only when the server advertises `listChanged`; a server that does not advertise it gets no refresh, and a call to a newly added tool is rejected client-side without any record. | obs (`Received .../list_changed notification`, in debug files), static (rest) |
| resources | Successful reads and lists leave **no record**. Failure-only records: `No displayable content found in MCP resource <uri>.`, error `resources/read returned <code> — resource not found`, error `resources/read returned -32601 MethodNotFound — ...`, `Failed to get MCP resources: <e>`, `Failed to fetch resource templates: <e>` | obs (no record on success), static (failures) |
| prompts | Prompt gets leave no record. `Error running command '<name>': <e>` | obs, static |
| skills, discovery cache, paging, subscriptions | `Found N skill(s) via skills/list`, `Loaded MCP skill '<n>' from <uri>`, `discovery-cache: ...`, `<method> still returning nextCursor after 20 pages; stopping`, `subscriptions/listen ...` | static |
| OAuth / XAA (~150 templates) | token store (`Returning tokens`, `Token length: N`, `Has refresh token: true\|false`, `Saving tokens`), refresh (`Starting token refresh`, `Token refresh successful`, ...), flow (`Starting SDK auth`, `Server URL: <url>` **S**, `Authorization URL: <url>`, `Opening authorization URL: <url>`), revocation, XAA (`XAA: secret lookup miss. ... configHeaders=<json>` **S**), `Authentication required for HTTP\|SSE\|claude.ai proxy server`. Token values are never logged; authorization URLs have `state`, `nonce`, `code_challenge`, `code_verifier`, `code` replaced, `client_id`, `redirect_uri`, `scope` kept. | static |
| config churn | `reconcileMcpServers: config changed, will replace (caller=<c>)`, `excludeStalePluginClients: marking stale (...)`, `applyConnectionResult: disposing orphaned connect (...)`, `In-process Chrome\|Computer Use MCP server started` | static |

### 2.8 What the MCP log never contains, and what it keeps in clear

| Never logged (obs) | Kept in clear (sensitive) |
|---|---|
| tool arguments and successful results, result size, spill files | connect-time stdio stderr (secrets echoed at start-up, environment dumps, warnings) |
| tool, resource and prompt descriptions; server `instructions` | HTTP/WS header values other than `*authorization`, after `${ENV}` expansion, plus `headersHelper` output |
| MCP `notifications/message` (server logging), progress notifications | URL query parameters (tokens), host names and ports |
| call-time stderr | tool error text (often derived from arguments) |
| approval-dialog answers, `/mcp` panel actions | elicitation questions and the **user's typed answers** |
| tool-use id, agent id, server name (except in the folder name) | `NO_PROXY` list and proxy host:port (userinfo is stripped) |
| stdio command, arguments and environment values (unless the server echoes them to stderr) | 80-character prefix of channel messages (static) |
| `Authorization` / `Proxy-Authorization` values | OAuth client ids, redirect URIs, scopes, endpoints (static) |

### 2.9 Distinguishing process kinds from the log alone

| Signal | Interactive TUI | Headless `-p` | `mcp list` / `mcp get` |
|---|---|---|---|
| `Channel notifications skipped` record | always | never | never |
| HTTP `User-Agent` in `HTTP transport options` | `claude-code/<v> (cli)` | `(sdk-cli)` | `(sdk-cli)` |
| stdio shutdown tail | SIGINT, SIGTERM, `exited cleanly` (no `closed`, no `Cleared connection cache`) | SIGINT, SIGTERM, `STDIO connection closed after Ns (cleanly)` (`UNKNOWN` for a `--mcp-config` entry without `type`, 2.7.5), `Cleared connection cache`, `exited cleanly` | as headless |
| HTTP shutdown tail | `dropped`, `Connection error`, `Terminal connection error 1/3` (no `closed`) | `HTTP connection closed`, `Cleared ...`, `dropped`, `Connection error`, `Terminal ...` | as headless |
| capabilities to shutdown gap | user-driven | at least one model round trip | tens of ms, never a `Calling` record; no transcript for the `sessionId` |

All obs.

---

## 3. `--debug` session file

### 3.1 Enablement

Debug mode is on if any of the following holds (argv is matched per element, up to the first `--`):

| Trigger | File | Status |
|---|---|---|
| `--debug` | yes, all categories | obs |
| `-d` | yes | static |
| `--debug=<filter>` | yes, filtered (3.3) | static |
| `--debug <word>` (space) | yes, **unfiltered**. The option takes an optional value, so `claude --debug mcp list` runs a headless session whose prompt is `list`, not `mcp list`. | static, consistent with obs |
| `--debug-file <p>` / `--debug-file=<p>` | yes, written to `path.resolve(p)` (implies debug mode) | static |
| `--debug-to-stderr`, `-d2e` | no file, lines go to stderr | static |
| env `DEBUG` or `DEBUG_SDK` in `1`, `true`, `yes`, `on` (any case) | yes. `DEBUG=express:*` style values do not count. | static |
| `/debug` slash command (interactive) | yes, **from that moment on**; the file then has no start-up lines | static |
| env `DEBUG_CLAUDE_AGENT_SDK` | separate `<cfg>/debug/sdk-<random uuid>.txt` written by an SDK host process, lines `<ISO> <message>` without a level; the same path is passed as `--debug-file` to the spawned CLI, giving a mixed-format file | static |

Nothing disables an active debug mode; only the level and the filter narrow it.

### 3.2 Path, naming, `latest`, rotation, retention

| Item | Behaviour | Status |
|---|---|---|
| Path | `--debug-file` if given, else `$CLAUDE_CODE_DEBUG_LOGS_DIR` (used as a **file** path despite its name), else `<cfg>/debug/<sessionId>.txt` with `<cfg>` = `$CLAUDE_CONFIG_DIR` or `~/.claude` (Windows: `%USERPROFILE%\.claude`). If the configured path is a directory (`EISDIR`), `<dir>/<sessionId>.txt` is used. | obs (default), static (others) |
| Session id in the name | Evaluated **per line at write time** (same getter as the MCP log's `sessionId`). One process can write several files (`--continue`, `--resume`, `/clear`) and one file can hold several processes. Custom paths collect every session id of the process in one file. | obs |
| `latest` | On the first successful append of each process: unlink `<dir>/latest`, then `symlink(<absolute debug path>, <dir>/latest)`, where `<dir>` is the folder of the debug file (with `--debug-file /x/y.log` the CLI replaces `/x/latest`). Not updated on a session switch: after `--continue` it points at the orphan file (3.6). Its mtime is about 15 ms after that process's first line. Retention skips it, so it can dangle. | obs |
| Rotation | When the per-process byte counter exceeds 10 MiB the file is renamed to `<name>.1.txt` (`<name>.1` if the name does not end in `.txt`), replacing an older `.1`; one generation only. | static |
| Retention | Every regular file in `<cfg>/debug/` except `latest` whose **mtime** is older than `cleanupPeriodDays` (default 30) is deleted, regardless of cwd. Same triggers as the MCP-log sweep (2.4). Invalid settings skip it and log `Skipping cleanup: settings have validation errors ...`. Files written through `--debug-file` or the env path are not swept. | static, obs (skip line) |
| Write path | Each line is its own `appendFile` on a serialized chain; an exit handler flushes the queue synchronously. A SIGKILL loses only in-flight appends. The folder is created on first write. | static |

### 3.3 Line layout

```
^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z) \[(?P<level>VERBOSE|DEBUG|INFO|WARN|ERROR)\] (?P<msg>.*)$
```

| Item | Behaviour | Status |
|---|---|---|
| Entry | `${new Date().toISOString()} [${LEVEL}] ${redact(message.trim())}\n`. Timestamp taken before redaction, UTC, ms. | obs |
| Levels | `verbose < debug < info < warn < error`. The minimum is `CLAUDE_CODE_DEBUG_LOG_LEVEL` (default `debug`), so VERBOSE lines are absent by default. A minimum above `debug` drops all DEBUG mirror lines but keeps ERROR mirror lines. | obs (DEBUG, INFO, WARN, ERROR), static (VERBOSE, level variable) |
| Filter | `--debug=a,b` keeps, `--debug=!a,!b` drops (mixing gives no filter). Categories: `MCP server "<name>"` lines give `mcp` and `<name lower-cased>`; a leading `<prefix>:` gives the prefix; `[tag]` gives the tag. `--debug=mcp` keeps the mirror lines and `[MCP] ...` lines. | static |
| Trimming | Leading and trailing whitespace is removed (a stderr record's trailing newline disappears). No escaping: raw control bytes (for example ESC) can occur. | obs |
| Multi-line entries | Internal `\n` are kept. Continuation lines have **no header**; the entry ends at the next header line. Producers: `Server stderr` mirror lines, `Permission suggestions for <tool>: [` (pretty JSON), some error messages. A continuation line can in principle look like a header (server stderr is arbitrary text). | obs |
| JSON output mode | Under `--output-format json` or `stream-json`, a message containing `\n` is `JSON.stringify`-ed **before** trimming and redaction: the message part then starts with `"` and its newlines are `\n` escapes, e.g. `[ERROR] "MCP server \"probe\" Server stderr: ready\n"`. Decode when the message starts with `"`. | obs |
| Encoding | UTF-8, LF only, no BOM. Split on `\n` only: generic line splitters also split on `\r`, `\x0b`, `\x0c`, `\x1c`-`\x1e`, `\x85`, U+2028/9, which can occur inside stderr. | obs |
| Process markers | Process start: first line `MDM settings load completed in Nms`; `Error log sink initialized` twice in the first ~50 lines. A segment appended by a resumed process starts without the MDM line. PIDs appear in `[uds-messaging] Listening: <dir>/<pid>.sock` (interactive). Shutdown: MCP shutdown mirror lines, `LSP server manager shut down successfully`, `BigQuery metrics exporter shutdown complete`. | obs |
| Entry point | `attribution header x-anthropic-billing-header: cc_version=<v>; cc_entrypoint=<cli\|sdk-cli>;` (`cli` = TUI, `sdk-cli` = headless) | obs |

### 3.4 Mirror of the MCP log

Each MCP-log record is produced by one call that first writes the debug line, then the MCP-log record:

| MCP-log record | Debug line | Status |
|---|---|---|
| `{"debug": msg}` | `<ts> [DEBUG] MCP server "<raw name>": <msg>` (colon after the name) | obs |
| `{"error": err}` | `<ts> [ERROR] MCP server "<raw name>" <String(err)>` (**no colon**). For an `Error` object the debug side has `Name: message` only, the MCP log has the full stack. | obs |

```
^MCP server "(?P<server>.+?)"(?P<sep>: | )(?P<text>.*)\Z      (DOTALL; DEBUG <-> ": ", ERROR <-> " ")
```

- The debug timestamp is never later than the MCP-log timestamp: observed offset 0 to 5 ms (mostly 0 or 1).
- Order is preserved; the debug file name (session id) equals the record's `sessionId`.
- The debug line carries the **raw** server name, so it resolves MCP-log folder collisions.
- Replayed (pre-sink) records share the replay timestamp in both files (static).
- No other debug call site starts with `MCP server "`. Look-alikes that are not mirror lines: `[MCP] Server "X" connected with subscribe=...`, `MCP server: ...`, `MCP servers blocked by managed policy ...`.
- A record present only in the debug file means the MCP-log copy was not written or not kept: a `Dropping log batch for <path>: <err>` line (write failure), records younger than the last flush at a SIGKILL, a sweep by file name date, a different `XDG_CACHE_HOME`, or later edits. A record present only in the MCP log means the debug copy was not written or not kept: debug mode not active then (`/debug` later, other process), a level or `--debug=` filter (DEBUG records only), rotation (`.1.txt`), retention, or a line written to another session's file. obs (write failure), static (others)

### 3.5 Redaction (debug copy only)

| Item | Behaviour | Status |
|---|---|---|
| Marker | `[REDACTED]`. Quotes around a captured value are kept (`"X-Api-Key":"[REDACTED]"`). An unquoted value is scanned as `[^\s,;&}\])]+`, which can swallow a closing quote, so a redacted JSON message may no longer parse. | obs |
| Rules | Seven low-confidence rules (URL userinfo, `Bearer`/`Basic` >= 20 chars, loose JWT, loose Anthropic key, cloud env vars, and **sensitive-assign**: a keyword such as `api_key`, `secret`, `token`, `password`, `credential`, `bearer`, `authorization`, `cookie`, `session_id`, `access_key`, `client_secret` followed by `=` or `:` and a value), then about 40 vendor token patterns (AWS, GCP, GitHub, GitLab, Slack, OpenAI, Anthropic, Stripe, PEM keys, ...). | obs (keyword rule), static (list) |
| Left in clear | Secrets without a keyword before `=` / `:` (a bare token in stderr, `?key=`, `?sig=`, `X-Tenant: ...`), and elicitation answers whose field name is not a keyword. | obs (bare stderr), static (elicitation) |
| Over-redaction | A **server name containing a keyword** (for example `secretsrv`, `tokenizer`) masks the first word of every DEBUG mirror line: `MCP server "secretsrv": [REDACTED] connection with timeout of 30000ms`. ERROR mirror lines are unaffected (no colon). Also non-secrets such as `autocompact: tokens=[REDACTED]`. | obs |
| Already masked in both copies | header names ending in `authorization`, proxy URL userinfo | obs |

### 3.6 Other MCP-relevant debug lines (not in the MCP log)

| Template / regex | Level | Evidence it adds | Status |
|---|---|---|---|
| `^\[Stall\] tool_dispatch_start tool=(\S+) toolUseId=(\S+) permissionDecisionMs=(\d+)$` | INFO | the **tool-use id** of the call (absent from the MCP log) and the time spent in the permission decision; written 0 to a few hundred ms before the mirrored `Calling MCP tool` line | obs |
| `^\[Stall\] tool_dispatch_end tool=(\S+) toolUseId=(\S+) outcome=(ok\|error\|aborted) durationMs=(\d+)$`, `^\[Stall\] tool_dispatch_post_error tool=(\S+) toolUseId=(\S+) durationMs=(\d+)$` | INFO | outcome and duration per tool-use id | obs, static |
| `^(\S+) tool permission denied$`, `^Permission suggestions for (\S+): (\[.*)\Z` (multi-line JSON), `^executePermissionRequestHooks called for tool: (\S+)$`, `^Slow permission decision: (\d+)ms for (\S+) \(mode=(\S+), behavior=(\S+)\)$` | DEBUG / INFO | permission decisions per tool | obs, static |
| `^Applying permission update: (Adding\|Removing) (\d+) (allow\|deny\|ask) rule\(s\) (to destination\|from source) '(\w+)': (\[.*\])$`, `^Persisting permission update: (\w+) to source '(\w+)'$`, `^Replacing all (allow\|deny\|ask) rules for destination '(\w+)' with (\d+) rule\(s\): (\[.*\])$` | DEBUG | rule changes and full rule state per source | obs |
| `^\[STARTUP\] Loading MCP configs\.\.\.$`, `^\[STARTUP\] MCP configs resolved in (\d+)ms ...`, `^mcp runtime arm: (v1\|v2) \(source: (\w+)\)$` (decides the capabilities JSON shape) | DEBUG | config loading | obs |
| `^\[MCP\] Server "(.+?)" connected with subscribe=(true\|false)$`, `^\[MCP\] Retry: (\d+) transiently-failed remote server\(s\) after (\d+)ms backoff$`, `^\[MCP\] (--mcp-config servers\|claude\.ai connectors) running fully async ...` | DEBUG | connections | obs |
| `^MCP config (skipped for\|read error for\|is not valid JSON:) (\S+) ...scope=(\w+)`, `^MCP config errors for (.+): (\[.*\])$`, `^Broken symlink or missing file encountered for settings.json at path: (.+)$`, `^\[claudeai-mcp\] ...` | DEBUG | which config sources and scopes existed | obs, static |
| `^Dropping log batch for (.+?): (.+)$` | DEBUG | the **only trace of a suppressed MCP log**, naming the would-be file | obs |
| `^Tool (mcp__\S+) not found in render-time tools$`, `^\[mcp\] (.+?): tools/list_changed refresh failed \((.+)\)` | ERROR / DEBUG | list_changed effects | obs, static |
| `^FileHistory: No need to copy file history for resuming with same session id: ([0-9a-f-]{36})$` | DEBUG | links an orphan file to the resumed session (3.7) | obs |
| `^Prior session exited uncleanly: ([0-9a-f-]{36}) \(v([^)]+)\)$` | DEBUG | the previous process of that session ended without cleanup (for example SIGKILL) | obs |
| `^Skipping cleanup: settings have validation errors ...` | DEBUG | retention sweep skipped | obs |

### 3.7 What the debug file never contains, and what it keeps in clear

- Never: tool arguments and results (as in the MCP log), anything before debug mode was enabled.
- In clear: everything listed in 2.8 that the keyword redactor does not match (3.5), plus local paths, PIDs, model names,
  the API base URL, request ids, permission rules, ToolSearch queries, and hook output.

---

## 4. Edge cases

| Case | MCP log | Debug file | Transcript | Status |
|---|---|---|---|---|
| `/clear` (interactive) | same file, no reconnect; `sessionId` switches to the new id, starting with a re-emitted `Channel notifications skipped` record about 1 s after `/clear` | later lines go to `<new id>.txt` without start-up lines; `latest` stays on the first file | new transcript file | obs (log), static (debug) |
| `--continue` | new file; **line 1 (`Starting connection`) carries a fresh session id that exists nowhere else**; from line 2 on, the continued id | the orphan `<fresh id>.txt` holds start-up and connect lines and ends with `FileHistory: ... same session id: <id>`; the rest is appended to `<id>.txt` without start-up lines; `latest` points to the orphan | the continued transcript is appended | obs |
| `--resume <id>` | new file; resumed id from line 1 (no orphan record) | orphan file as for `--continue` | appended | obs (interactive), static (headless) |
| Sub-agent (Agent tool) | calls logged under the **parent** session id; the log cannot tell delegated from direct calls | in the parent's file | `<parent>/subagents/agent-<id>.jsonl` records carry the parent `sessionId`, `agentId`, `isSidechain: true`; the tool-use id is in that file | obs (log, transcript), static (debug) |
| `--no-session-persistence` | normal | normal | none: the log is the only host record of the call | obs (log) |
| `mcp list` / `mcp get` | full connect and shutdown under a fresh session id per process | only via `DEBUG=1` (subcommands have no `--debug`) | none | obs (log), static (debug) |
| Interactive session without a prompt | connect and shutdown records | | transcript without messages | obs |
| SIGKILL | last ~1 s lost, possibly no file; a call without completion; no shutdown records | lines up to ms before the kill; the next start logs `Prior session exited uncleanly: <id>` | `tool_use` without result | obs (log), static (debug) |
| Rejected client-side (`No such tool available`, headless permission not granted) | nothing | permission lines | `tool_use` and error `tool_result` | obs |
| Interactive user denial | nothing | | | static |
| Graceful shutdown with a call in flight (SIGTERM, `/exit`) | `failed after Ns: MCP error -32001: AbortError: shutdown` (headless SIGTERM) or `... MCP error -32000: Connection closed` (interactive `/exit`) inside the shutdown records (2.7.3) | | error `tool_result` (the interrupt text, or the MCP error) | obs |
| User abort (Esc) during a call | not observed | | | |
| Name collision | one interleaved file per process (duplicate `Starting connection`, two stderr blobs) | raw names | raw names (`_` and `-` kept) | obs |
| Keyword in server name | unaffected | first word of DEBUG mirror lines masked | unaffected | obs |
| Parallel calls | tools without `readOnlyHint` run serially even when requested in one message; read-only tools can overlap, and two in-flight calls of the same tool cannot be told apart in the log | | each result is its own record | obs (serial), static (overlap) |
| Interactive vs headless | markers in 2.9 | `cc_entrypoint=cli\|sdk-cli` | `entrypoint` field | obs |
| Write blocked | no file | `Dropping log batch for <path>: <err>` | normal | obs |
| Same-ms start, same cwd | two processes append to one file | | | static |

---

## 5. How MCPeek joins the logs to the transcript

MCPeek reports what each join found and how; it never interprets an offset or a missing record.

| Join | Key and rule |
|---|---|
| Call to completion (one MCP-log file) | FIFO per raw tool name. If two calls of the same tool are in flight, the pairing is flagged as ambiguous. Heartbeats attach to the oldest open call of that tool. A call without completion is reported as "no completion record". |
| Debug file to MCP log | A mirror line and a record must agree on `enc(raw name) == folder`, kind (DEBUG/`debug`, ERROR/`error`) and time (`log - debug` within -5 to +50 ms), preferring records whose `sessionId` equals the debug file's session id (a match across session ids is counted as a session mismatch). Text is "identical" after trimming, "redaction-only" when each `[REDACTED]` may stand for any text (values that are `[REDACTED]` in both copies are not counted), or "error-object" when the debug text is the first line of the logged stack. Assignment is greedy in file order, smallest offset first. Leftovers of the same template within the window are paired as "differs from debug copy"; the rest is reported as MCP-log only or debug only, with any `Dropping log batch` lines as context. Offsets outside 0 to 5 ms and order inversions are counted. |
| Retry after session recovery | A `Retrying tool 'T' after session recovery` record links two calls of T in one MCP-log file or one server's mirror lines of one debug file: the most recent `failed after` record of T before it (within 10 s) ends the first attempt, and the next `Calling MCP tool: T` after it (within 120 s) starts the retry. No link is made across a process start, when a connection attempt fails in between, or (debug file) when a `tool_dispatch_start` of the same tool lies between the `Retrying` line and that `Calling` line. Two calls of the same tool are never linked on timing alone. The linked attempts are reported as one call: source and start are the first `Calling` record, outcome, duration and completion are those of the last attempt (the completion-minus-Calling delta spans both attempts), and the notes say `retried after session recovery; first attempt failed after Ns` and list both attempts with their records (lines), durations and the first attempt's error text (withheld). The `Retrying tool` event names both `Calling` records (`retry_of_call`, `retry_calling`). With a debug file, the retry's `Calling` line is not paired with a `tool_dispatch_start`; the call keeps the dispatch of the first attempt, and a note states whether that dispatch's start and end lines enclose both attempts. The single call joins to the single transcript `tool_use` by the rules below. |
| Debug-only calls and events | A mirrored call or event whose MCP-log twin is missing (write failure, SIGKILL, retention) is reconstructed from the debug lines and labelled as such. |
| Log call to transcript `tool_use`, debug file present | `[Stall] tool_dispatch_start ... toolUseId=<id>` is paired FIFO with the next mirrored `Calling MCP tool` of the same server and tool in the same debug file (within 10 s); through the cross-check this pins the MCP-log call. The transcript `tool_use` with that id **and** the same session id is the match (ids from some gateways repeat across sessions). |
| Log call to transcript `tool_use`, otherwise | Same `sessionId` (sub-agent sidecars included: they carry the parent id), `enc(server segment of mcp__<server>__<tool>) == folder`, `enc(tool) == enc(logged tool)`. Candidates are unassigned `tool_use` records not later than the log call (+50 ms) and not earlier than 60 s before it when the file carries headless markers (2.9), 24 h otherwise (an approval dialog delays interactive calls; observed 1 to 40 ms headless, up to minutes interactive). A candidate whose `tool_result` is more than 50 ms before the log completion or more than 10 s after it is dropped (observed 0 to about 350 ms). The candidate whose result follows the completion most closely wins, then the earliest `tool_use`. A tie is reported as "ambiguous" with all candidates; no candidate as "unmatched" (log-only). Nothing is forced. |
| Transcript call without log record | Reported as "no log record", with whether an MCP log of that server holds records of that session. Normal causes: client-side rejection, permission not granted, SIGKILL before the flush, write failure, retention, another host. |
| Log call without transcript call | Reported as a log-only row (`--no-session-persistence`, `mcp list/get`, deleted or swept transcripts, a transcript folder outside the examined tree). Its depth, sidechain flag and transcript-result fields are empty: the log cannot tell a delegated call from a direct one. |
| Shutdown events | Shutdown records within 2 s of each other form one event. It is a `shutdown` when it holds a process-control step (SIGINT, SIGTERM, SIGKILL, `exited cleanly`), `connection closed` or `Cleared connection cache`, or when it is the interactive HTTP tail (2.9): `dropped` and `Terminal connection error`, possibly with `Connection error`, and nothing else, with no record of that file after it (in a debug file: no record of that server after it before the next process start), in a file marked interactive. Any other group, for example a transport error followed by more records, is a `transport-error`. |
| Tool error text | An error record followed within three records by a `failed after` record with the same text is withheld as tool error text, whatever form the text has. Free error text (matching no template, or an error object or stack) written while a call of the same file is in flight is withheld the same way. |
| Other withheld text | The message part of connection, transport and other error templates (`Connection failed ...: <message>`, `Connection error: <message>`, `Error during close: <message>`, ...) is withheld as `error-text`, and so is the whole text of an error record whose template is not known to hold only fixed text. The text of a record that matches no template is withheld as `unclassified-text`. Elicitation requests withhold the question and the whole `requestedSchema` (defaults, titles, enum values). In `HTTP transport options` and `WebSocket transport options`, each header value other than `User-Agent`, `Accept-Encoding` and `[REDACTED]` is withheld as `http-header`, whatever whitespace the JSON has; a `headers` object that does not parse as JSON with string values only (for example after the debug redactor swallowed a closing quote, 3.5) is withheld whole as one `http-header` item. URL userinfo, query values and fragments are withheld wherever a URL occurs: a query value runs to the next `&` or `#` and a fragment to the end of the URL, including quotes, `<`, `>` and spaces. A URL inside a JSON string ends at the closing quote; elsewhere in free text it runs to the end of the line once its query or fragment has started. In a transport-options message whose JSON does not parse (a raw quote in the URL, or a quote the debug redactor swallowed), the `url` value is withheld as one item from its userinfo, first query value or fragment to the end of the value (before the last `headers` member), so a quote inside it cannot end it early. Template fields that are not free text (outcome, ms, code, transport, tool) stay visible. Size and SHA-256 prefix of a withheld value cover exactly the bytes `--show-sensitive` prints; the debug copy of a message is trimmed by the CLI, so a value at the end of a message can differ there by surrounding whitespace. |
| Repeated debug entries | A debug file that repeats entries of an earlier one (for example a regular-file copy of `latest` that is a few lines longer or shorter than the session file) has each repeated entry (same level, server, text and timestamp) noted and counted once, from the earlier file. |
| Timestamps | Compared and ordered in UTC; displayed as recorded. An ISO offset (`+02:00`) is accepted wherever a timestamp is parsed (the CLI itself writes `Z`). A timestamp without a zone or not in ISO 8601 form cannot be ordered: its row is listed after the timed rows and a warning names the file and line. |
| `/clear`, `--continue`, collisions | Each record carries its own `sessionId`, so calls join to the right transcript; a mid-file switch is listed as its own row. A single leading record with a session id that appears nowhere else is reported as the `--continue` pattern. In a shared (collision) folder, the matched transcript call names the server of each call and its log call is counted under that server; other calls and events of the folder are labelled `<folder> (shared by: a, b)`. With at most one known name, a file with signs of several servers (connection attempts that overlap, or a shutdown that repeats a once-per-server step: `connection closed`, `Cleared connection cache`, SIGTERM) is flagged as possibly shared by servers whose names sanitize to the folder name, and its unattributed calls and events are labelled so. Shutdown records name no server: they are reported as one event covering every server of the folder, or split per server when debug mirror lines name the server of every record. |
