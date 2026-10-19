"""Pydantic v2 entity models for MCPeek.

Field lists here are deliberately conservative: every field is something
observed in real Claude Code CLI ``~/.claude.json`` / ``~/.claude/``
artifact trees. We do not model fields that "should" exist per the MCP
spec but that were never observed in a real ``.credentials.json`` /
``.claude.json`` (see README "Scope and limitations").
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class Transport(str, Enum):
    """A server's configured ``type`` (``stdio`` when absent and a command is
    configured, ``http`` when absent and a URL is). Any other ``type`` value is
    ``unknown`` and kept as written in ``Server.type_raw``."""

    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"
    WS = "ws"
    SSE_IDE = "sse-ide"
    WS_IDE = "ws-ide"
    CLAUDEAI_PROXY = "claudeai-proxy"
    UNKNOWN = "unknown"


class ClientIdKind(str, Enum):
    """How an MCP OAuth client registered itself with the authorization server."""

    DCR = "dcr"  # Dynamic Client Registration: opaque server-issued UUID/id
    CIMD = "cimd"  # Client ID Metadata Document: a dereferenceable https:// URL
    UNKNOWN = "unknown"


class DenialKind(str, Enum):
    USER_REJECTED = "user-rejected"
    PERMISSION_RULE = "permission-rule"
    OTHER = "other"


class DebugServerInfo(BaseModel):
    """MCP server connection facts recovered from a ``--debug`` file line
    ``MCP server "<name>": Connection established with capabilities: {...}``.

    Presence-dependent: only populated when a debug file exists. The
    capabilities JSON has two shapes: runtime arm v1 has
    ``hasTools..serverVersion`` only, arm v2 adds ``protocolEra`` and
    ``negotiatedProtocolVersion``. ``serverVersion`` is the server's
    self-reported serverInfo object or the string "unknown".
    """

    model_config = ConfigDict(extra="forbid")

    server_name: str
    negotiated_protocol_version: Optional[str] = None
    server_version_name: Optional[str] = None
    server_version_version: Optional[str] = None
    server_version_text: Optional[str] = None  # set when serverVersion is a string (e.g. "unknown")
    protocol_era: Optional[str] = None
    runtime_arm: Optional[str] = None  # from "mcp runtime arm: v1|v2 (...)", if logged before
    has_tools: Optional[bool] = None
    has_prompts: Optional[bool] = None
    has_resources: Optional[bool] = None
    transport: Optional[str] = None
    connect_ms: Optional[int] = None
    timestamp: Optional[str] = None
    debug_log_path: str
    debug_log_line: Optional[int] = None
    source_session_uuid: Optional[str] = None


class Server(BaseModel):
    """An MCP server configuration entry.

    Source: ``.claude.json``'s ``mcpServers`` (global/user scope) and
    ``projects.<cwd>.mcpServers`` (per-project scope). Project-level
    ``.mcp.json`` manifests are looked up only at literal project roots
    (never via a recursive glob -- see loader.py).
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    scope: str  # "user" (global mcpServers) or a project cwd path
    transport: Transport = Transport.UNKNOWN
    type_raw: Optional[str] = None  # the configured "type" as written when it is not a known transport
    command: Optional[str] = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    url: Optional[str] = None
    headers: dict[str, str] = Field(default_factory=dict)  # HTTP/SSE/WS headers as configured (before ${ENV} expansion)
    headers_helper: Optional[str] = None  # headersHelper command that prints dynamic headers
    oauth: Optional[dict[str, Any]] = None  # the configured "oauth" object (clientId, callbackPort, ...) as written
    source_path: str  # on-disk file this entry was read from
    debug_info: list[DebugServerInfo] = Field(default_factory=list)
    log_info: list["LogServerSummary"] = Field(default_factory=list)
    # URLs of log_info[].log_urls whose recorded value equals url (shown once, as configured)
    log_urls_matching_url: list[str] = Field(default_factory=list)


class Tool(BaseModel):
    """An MCP tool invocation surface, derived from observed ``mcp__<server>__<tool>``
    tool_use names in transcripts. MCPeek never recovers tool descriptions or
    JSON schemas -- those are not persisted anywhere on disk.
    """

    model_config = ConfigDict(extra="forbid")

    server_name: str
    tool_name: str
    call_count: int = 0  # tool_use blocks in transcripts
    sessions: list[str] = Field(default_factory=list)  # sorted session ids of those tool_use blocks
    log_call_count: int = 0  # "Calling MCP tool" records in MCP logs / debug mirror lines
    log_failed_count: int = 0  # "failed after" records
    log_sources: list[str] = Field(default_factory=list)
    # Set on rows that count MCP-log calls by log folder: calls in a folder
    # shared by several server names that matched no single transcript call.
    log_folder: Optional[str] = None
    server_candidates: list[str] = Field(default_factory=list)


class Subagent(BaseModel):
    """A delegated sub-agent, identified by the ``agent-<agentId>`` sidecar pair.

    ``agent_id`` is derived from the sidecar filename (or the ``agentId``
    field present on records inside ``agent-<id>.jsonl``) -- it is NOT a
    field inside ``agent-<id>.meta.json`` itself. The meta file only ever
    carries ``{agentType, description, toolUseId, spawnDepth,
    [parentAgentId]}``.
    """

    model_config = ConfigDict(extra="forbid")

    agent_id: str
    agent_type: Optional[str] = None
    description: Optional[str] = None
    tool_use_id: str  # the toolu_... id of the spawning Agent-tool call
    spawn_depth: Optional[int] = 1  # 1 if the meta file has no spawnDepth; None if it is not an integer
    parent_agent_id: Optional[str] = None
    session_uuid: str
    sidecar_path: str


class ToolCall(BaseModel):
    """One tool invocation, stitched from tool_use -> tool_result via id.

    ``row_kind`` is "tool-call" for transcript calls. Calls that exist only in
    an MCP log or debug file are emitted as "log-only-call" rows, and log calls
    that fit more than one transcript call as "log-call-ambiguous" rows; both
    have ``source_path`` pointing at the log and ``tool_use_id`` None unless
    a debug file supplied it.
    """

    model_config = ConfigDict(extra="forbid")

    row_kind: str = "tool-call"
    tool_use_id: Optional[str]
    tool_name: str
    is_mcp: bool = False
    mcp_server: Optional[str] = None
    mcp_tool: Optional[str] = None
    timestamp: Optional[str] = None
    session_uuid: str
    cwd: Optional[str] = None
    # None on log rows: the MCP log cannot tell delegated from direct calls.
    is_sidechain: Optional[bool] = False
    agent_id: Optional[str] = None  # set when this call happened inside a subagent
    spawn_depth: Optional[int] = 0  # 0 = main session, 1+ = nested subagent depth, None on log rows
    input_summary: Optional[str] = None  # transcript tool_use input (can hold any argument value)
    # transcript tool_result; None on log rows (no transcript result exists)
    result_found: Optional[bool] = False
    result_is_error: Optional[bool] = False
    result_summary: Optional[str] = None
    spill_path: Optional[str] = None  # resolved path to spilled tool-results/*.txt, if any
    denied: bool = False
    denial_kind: Optional[DenialKind] = None
    is_spawn: bool = False  # True if this tool_use spawned a subagent (id-stitch to meta.json)
    spawned_agent_id: Optional[str] = None
    result_timestamp: Optional[str] = None
    source_path: Optional[str] = None  # transcript / sidecar file (or log file:line for log-only rows)
    source_line: Optional[int] = None  # line of the tool_use record in source_path (transcript rows)
    log: Optional["ToolCallLogInfo"] = None  # MCP log / debug evidence for this call (MCP calls only)


class OAuthClient(BaseModel):
    """One ``mcpOAuth`` entry from ``.credentials.json``.

    Field list matches exactly what was observed on disk:
    ``serverName, serverUrl, clientId, issuer, redirectUri, discoveryState,
    accessToken`` (plus sometimes ``refreshToken``). No ``scope``/expiry
    field is modeled -- it is not reliably present, and actual token
    values are never emitted by MCPeek (always redacted/omitted).
    """

    model_config = ConfigDict(extra="forbid")

    key: str  # the "<serverName>|<hash>" key under mcpOAuth
    server_name: str
    server_url: Optional[str] = None
    client_id: Optional[str] = None
    client_id_kind: ClientIdKind = ClientIdKind.UNKNOWN
    issuer: Optional[str] = None
    redirect_uri: Optional[str] = None
    discovery_state: dict[str, Any] = Field(default_factory=dict)
    has_access_token: bool = False
    has_refresh_token: bool = False
    source_path: str


class Grant(BaseModel):
    """A permission grant (``permissions.allow`` of a ``settings.local.json``)
    or a project ``.mcp.json`` server approval (``enabledMcpjsonServers``,
    ``disabledMcpjsonServers``, ``enableAllProjectMcpServers`` of a
    ``settings.local.json`` or of a ``.claude.json`` project entry)."""

    model_config = ConfigDict(extra="forbid")

    kind: str = "permission-allow"  # permission-allow | mcpjson-enabled | mcpjson-disabled | mcpjson-enable-all
    tool_name: Optional[str] = None  # permission-allow: the allowed tool (rule text)
    is_mcp: bool = False
    mcp_server: Optional[str] = None  # server of an mcp__ tool, or the .mcp.json server enabled/disabled
    mcp_tool: Optional[str] = None
    value: Optional[bool] = None  # mcpjson-enable-all: the enableAllProjectMcpServers value
    field: str = "permissions.allow"  # the key the entry was read from
    note: Optional[str] = None  # e.g. a wildcard in the server position: listed as written, not mapped to servers
    scope: str  # "user", a project path, or "user + project <path>" (project at HOME: same file)
    source_path: str


class Session(BaseModel):
    """One Claude Code session transcript."""

    model_config = ConfigDict(extra="forbid")

    session_uuid: str
    project_dir_encoded: str  # the "-root-proj-x" directory name on disk
    transcript_path: str
    cwds: list[str] = Field(default_factory=list)  # sorted cwd values seen on records
    first_timestamp: Optional[str] = None
    last_timestamp: Optional[str] = None
    version: Optional[str] = None
    message_count: int = 0
    tool_call_count: int = 0
    mcp_tool_call_count: int = 0
    subagent_count: int = 0
    has_subagent_dir: bool = False
    has_tool_results_dir: bool = False


class ProjectDir(BaseModel):
    """A project path of the examined host and where it lies in the target."""

    model_config = ConfigDict(extra="forbid")

    path: str  # as recorded (.claude.json projects key, transcript cwd)
    sources: list[str] = Field(default_factory=list)
    target_path: Optional[str] = None  # the folder under the target root; None if not inside HOME
    in_target: bool = False  # target_path exists


class SkippedSymlink(BaseModel):
    """A symlink MCPeek did not follow because it leads outside the target root."""

    model_config = ConfigDict(extra="forbid")

    path: str
    target: Optional[str] = None  # readlink() text
    looked_up_as: str


class PathAlias(BaseModel):
    """A path inside the target that resolves (through a symlink) to a file or
    folder MCPeek already read under another path; it is read once."""

    model_config = ConfigDict(extra="forbid")

    path: str  # the path that was not read again
    target: Optional[str] = None  # readlink() text of the symlink on the way, if one was found
    same_as: str  # the path that was read
    looked_up_as: str


class FilteredFile(BaseModel):
    """Calls and events of other sessions in one kept MCP-log or --debug file,
    left out of the views under a session filter."""

    model_config = ConfigDict(extra="forbid")

    path: str
    log_calls: int = 0
    server_events: int = 0
    records: int = 0  # MCP-log records or --debug entries not listed by `logs`
    sensitive_items: int = 0  # withheld values of other sessions' records taken out of the rows kept
    session_ids: list[str] = Field(default_factory=list)  # the other session ids ("" for calls without one)
    pairing_only: bool = False  # read only to pair --debug mirror lines as an unfiltered run does; not shown


class SessionFilter(BaseModel):
    """The active --session / --project filter and what it left out."""

    model_config = ConfigDict(extra="forbid")

    session_values: list[str] = Field(default_factory=list)  # --session values as given
    project_values: list[str] = Field(default_factory=list)  # --project values as given
    session_ids: list[str] = Field(default_factory=list)  # the selected session ids
    project_dirs: list[str] = Field(default_factory=list)  # project folders of the selected transcripts
    transcript_files_total: int = 0  # transcript files found (counted by name)
    transcript_files_selected: int = 0
    transcript_paths: list[str] = Field(default_factory=list)
    # None for `sessions --quick`, which reads no log
    mcp_log_files_total: Optional[int] = None
    mcp_log_files_kept: Optional[int] = None  # shown: a selected session appears in them
    mcp_log_files_pairing_only: Optional[int] = None
    debug_files_total: Optional[int] = None
    debug_files_kept: Optional[int] = None  # shown: named after, or paired with records of, a selected session
    debug_files_pairing_only: Optional[int] = None
    log_calls_filtered_out: Optional[int] = None
    server_events_filtered_out: Optional[int] = None
    records_filtered_out: Optional[int] = None
    sensitive_items_filtered_out: Optional[int] = None
    filtered_out_by_file: list[FilteredFile] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class Case(BaseModel):
    """The top-level parsed target: everything MCPeek recovered from one home-like root."""

    model_config = ConfigDict(extra="forbid")

    target_root: str
    home: Optional[str] = None  # HOME of the examined host that the target root stands for
    home_source: str = "not determined"  # how HOME was determined
    projects: list[ProjectDir] = Field(default_factory=list)
    servers: list[Server] = Field(default_factory=list)
    tools: list[Tool] = Field(default_factory=list)
    sessions: list[Session] = Field(default_factory=list)
    subagents: list[Subagent] = Field(default_factory=list)
    tool_calls: list[ToolCall] = Field(default_factory=list)
    oauth_clients: list[OAuthClient] = Field(default_factory=list)
    grants: list[Grant] = Field(default_factory=list)
    cache_roots: list["CacheRoot"] = Field(default_factory=list)
    mcp_log_files: list["McpLogFile"] = Field(default_factory=list)
    debug_files: list["DebugFile"] = Field(default_factory=list)
    debug_latest_links: list["LatestLink"] = Field(default_factory=list)
    log_servers: list["LogServerSummary"] = Field(default_factory=list)
    log_calls: list["LogCall"] = Field(default_factory=list)
    server_events: list["ServerEvent"] = Field(default_factory=list)
    cross_check: Optional["CrossCheck"] = None
    sensitive_values_shown: bool = False
    skipped_symlinks: list[SkippedSymlink] = Field(default_factory=list)
    path_aliases: list[PathAlias] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    # set under --session / --project; added to JSON output as "filter" by the
    # renderer (excluded here, so that unfiltered output is unchanged)
    filter: Optional[SessionFilter] = Field(default=None, exclude=True)


# ---------------------------------------------------------------------------
# MCP log and --debug file entities
# ---------------------------------------------------------------------------


class SensitiveItem(BaseModel):
    """A value MCPeek withholds unless --show-sensitive is given.

    ``value`` is None unless the examiner opted in. ``size_bytes`` and
    ``sha256_prefix`` (first 12 hex digits of SHA-256) are computed over
    exactly the UTF-8 bytes of the value that --show-sensitive prints (a
    correlation aid, not a protection: short values can be guessed from it).
    """

    model_config = ConfigDict(extra="forbid")

    kind: str  # stderr, http-header, url-query, url-userinfo, url-fragment, url-unparsed, tool-error-text, error-text,
    #            unclassified-text, elicitation-question, elicitation-schema, elicitation-answer,
    #            proxy-setting, node-options, channel-message, server-output, permission-rules,
    #            unparsed-line, masked-by-debug-redactor
    field: Optional[str] = None  # header name, query parameter, JSON key
    size_bytes: int
    sha256_prefix: str
    source: str  # file:line
    value: Optional[str] = None


class LoggedDuration(BaseModel):
    """A duration as the CLI logged it, with its precision kept.

    "15ms" is exact. "3s" means 3000 <= ms <= 3999 (the CLI floors), and
    "1m 5s" means 65000 <= ms <= 65999. ``failed after Ns`` is always whole
    seconds.
    """

    model_config = ConfigDict(extra="forbid")

    text: str
    unit: str  # "ms" | "s" | "m s"
    min_ms: int
    max_ms: int
    exact: bool


class CacheRoot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str  # the claude-cli-nodejs directory
    origin: str  # linux-default | macos-default | windows-default | cli-option | found-in-target
    status: str  # "observed" or "static" (location taken from the bundle, not observed)
    log_files: int = 0


class McpLogRecord(BaseModel):
    """One line of a per-server MCP log, classified against the catalog."""

    model_config = ConfigDict(extra="forbid")

    line: int
    key: str  # debug | error | invalid
    timestamp: Optional[str] = None
    session_id: Optional[str] = None
    cwd: Optional[str] = None
    message_id: str  # catalog id, "tool.error_text", "unclassified" or "invalid"
    category: str
    catalog_status: str  # observed | static | unclassified
    text: str  # message, with sensitive parts withheld unless --show-sensitive
    fields: dict[str, Any] = Field(default_factory=dict)
    sensitive: list[SensitiveItem] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class SessionSwitch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    line: int
    timestamp: Optional[str] = None
    from_session: Optional[str] = None
    to_session: Optional[str] = None


class McpLogFile(BaseModel):
    """Summary of one ``mcp-logs-<server>/<start>.jsonl`` file."""

    model_config = ConfigDict(extra="forbid")

    path: str
    cache_root: str
    encoded_cwd: str
    server_dir: str  # folder suffix after "mcp-logs-" (sanitized server name)
    server: str  # display name: the unique candidate, else the folder suffix
    name_candidates: list[str] = Field(default_factory=list)
    name_status: str = "unknown"  # unique | ambiguous | unknown
    file_name_time: Optional[str] = None  # process start time from the file name (UTC)
    file_name_conforms: bool = True
    size_bytes: int = 0
    lines: int = 0
    record_count: int = 0
    classified: int = 0
    unclassified: int = 0
    invalid_lines: list[int] = Field(default_factory=list)
    empty_lines: int = 0
    unterminated_last_line: bool = False
    extra_keys: list[str] = Field(default_factory=list)
    first_timestamp: Optional[str] = None
    last_timestamp: Optional[str] = None
    timestamp_decreases: int = 0
    session_ids: list[str] = Field(default_factory=list)
    session_switches: list[SessionSwitch] = Field(default_factory=list)
    leading_single_record_session: Optional[str] = None  # --continue orphan id pattern
    cwds: list[str] = Field(default_factory=list)
    process_markers: list[str] = Field(default_factory=list)
    mode: str = "unknown"  # interactive | headless-or-mcp-list | unknown (from markers)
    overlapping_connects: bool = False  # concurrent connection attempts in one file
    # signs that several servers write to this file (overlapping connection
    # attempts, repeated shutdown steps); "possibly shared" when the folder
    # name has at most one known candidate
    shared_folder_signs: list[str] = Field(default_factory=list)
    possibly_shared: bool = False
    counts_by_message: dict[str, int] = Field(default_factory=dict)
    tool_calls: int = 0
    connect_attempts: int = 0
    shutdown_records: int = 0
    sensitive_item_count: int = 0
    notes: list[str] = Field(default_factory=list)
    entries: list[McpLogRecord] = Field(default_factory=list, exclude=True)


class DebugEntry(BaseModel):
    """An MCP-relevant entry of a --debug file (mirror line or catalog line)."""

    model_config = ConfigDict(extra="forbid")

    line: int
    end_line: int
    timestamp: Optional[str] = None
    level: Optional[str] = None
    json_encoded: bool = False
    mirror: bool = False  # 'MCP server "<name>"...' line
    server: Optional[str] = None  # raw server name on a mirror line
    message_id: str
    category: str
    catalog_status: str
    text: str
    fields: dict[str, Any] = Field(default_factory=dict)
    sensitive: list[SensitiveItem] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class DebugFile(BaseModel):
    """Summary of one --debug file."""

    model_config = ConfigDict(extra="forbid")

    path: str
    origin: str  # debug-dir | cli-option
    name_kind: str  # session | rotated | sdk | latest-copy | other
    session_id: Optional[str] = None
    session_id_source: str = "unknown"  # file name | file name (rotated) | matched MCP log records | unknown
    size_bytes: int = 0
    lines: int = 0
    entry_count: int = 0  # entries (header line plus continuation lines)
    continuation_lines: int = 0
    json_encoded_entries: int = 0
    lines_before_first_header: int = 0
    timestamp_decreases: int = 0
    levels: dict[str, int] = Field(default_factory=dict)
    first_timestamp: Optional[str] = None
    last_timestamp: Optional[str] = None
    process_starts: int = 0
    pids: list[str] = Field(default_factory=list)
    entrypoints: list[str] = Field(default_factory=list)
    runtime_arms: list[str] = Field(default_factory=list)
    mirror_lines: int = 0
    mirror_unclassified: int = 0
    servers: list[str] = Field(default_factory=list)
    dispatch_starts: int = 0
    permission_denials: int = 0
    resumes_session: Optional[str] = None  # from "FileHistory: ... same session id: <id>"
    prior_unclean_sessions: list[str] = Field(default_factory=list)
    log_batches_dropped: list[str] = Field(default_factory=list)  # paths named by "Dropping log batch for"
    has_transcript: Optional[bool] = None
    sensitive_item_count: int = 0
    # entries that repeat an entry of an earlier debug file (same server, text and
    # timestamp): counted once, from the earlier file
    duplicate_entries: int = 0
    duplicates_of: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    mcp_entries: list[DebugEntry] = Field(default_factory=list, exclude=True)


class LatestLink(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    kind: str  # symlink | regular-file
    target: Optional[str] = None  # readlink() text, never followed
    resolves_to: Optional[str] = None  # file in the same folder the target names, if present
    identical_to: Optional[str] = None  # for a regular-file copy: debug file with identical bytes


class DebugDispatch(BaseModel):
    """[Stall] tool_dispatch_start / _end lines for one tool-use id."""

    model_config = ConfigDict(extra="forbid")

    tool: str
    tool_use_id: str
    permission_decision_ms: Optional[int] = None
    outcome: Optional[str] = None
    duration_ms: Optional[int] = None
    start_source: str
    end_source: Optional[str] = None


class LogCall(BaseModel):
    """One MCP tool call as recorded by the per-server MCP log (or, when no
    MCP-log record exists, by a --debug mirror line), with its join result."""

    model_config = ConfigDict(extra="forbid")

    source_kind: str  # mcp-log | debug-mirror
    source: str  # file:line of the "Calling MCP tool" record
    end_source: Optional[str] = None
    debug_copy: Optional[str] = None  # debug file:line of the mirrored Calling line
    server: str
    server_dir: str
    server_candidates: list[str] = Field(default_factory=list)
    tool: str
    session_id: Optional[str] = None
    cwd: Optional[str] = None
    start_timestamp: Optional[str] = None
    end_timestamp: Optional[str] = None
    outcome: str  # completed | failed | no completion record
    duration: Optional[LoggedDuration] = None
    timestamp_delta_ms: Optional[int] = None  # completion record ts - Calling record ts
    heartbeats_s: list[int] = Field(default_factory=list)
    error_text: Optional[str] = None  # withheld unless --show-sensitive
    sensitive: list[SensitiveItem] = Field(default_factory=list)
    concurrent_calls: int = 0  # other calls of this file in flight at start
    completion_pairing: str = "fifo"  # fifo | fifo, same tool in flight (ambiguous)
    process_mode: str = "unknown"
    dispatch: Optional[DebugDispatch] = None
    join_status: str = "unmatched"  # matched | ambiguous | unmatched
    join_method: Optional[str] = None
    tool_use_id: Optional[str] = None
    candidate_tool_use_ids: list[str] = Field(default_factory=list)
    call_offset_ms: Optional[int] = None  # log Calling - transcript tool_use
    result_offset_ms: Optional[int] = None  # transcript tool_result - log completion
    transcript_path: Optional[str] = None
    agent_id: Optional[str] = None
    notes: list[str] = Field(default_factory=list)


class ToolCallLogInfo(BaseModel):
    """MCP log / debug evidence attached to a transcript MCP call."""

    model_config = ConfigDict(extra="forbid")

    status: str  # matched | ambiguous | no log record
    method: Optional[str] = None
    source: Optional[str] = None
    source_kind: Optional[str] = None
    outcome: Optional[str] = None
    duration: Optional[LoggedDuration] = None
    end_timestamp: Optional[str] = None  # timestamp of the log completion record
    timestamp_delta_ms: Optional[int] = None
    call_offset_ms: Optional[int] = None
    result_offset_ms: Optional[int] = None
    heartbeats_s: list[int] = Field(default_factory=list)
    dispatch: Optional[DebugDispatch] = None
    candidate_sources: list[str] = Field(default_factory=list)  # log calls (file:line) that fit this transcript call
    candidate_tool_use_ids: list[str] = Field(default_factory=list)  # transcript calls that fit this log call
    log_file_for_session: Optional[bool] = None  # an MCP log of this server has records of this session
    notes: list[str] = Field(default_factory=list)


class ServerEvent(BaseModel):
    """A server lifecycle or other non-call event from an MCP log or debug file."""

    model_config = ConfigDict(extra="forbid")

    row_kind: str = "server-event"
    event: str  # connect | shutdown | transport-error | elicitation | roots-request | list-changed |
    #             session-switch | reconnect | resource | prompt | tool-schema | oauth | channel |
    #             config | unclassified | mcp-log-write-dropped | permission-denied | ...
    timestamp: Optional[str] = None
    end_timestamp: Optional[str] = None
    session_uuid: Optional[str] = None
    cwd: Optional[str] = None
    server: str
    server_dir: str
    server_candidates: list[str] = Field(default_factory=list)
    summary: str
    fields: dict[str, Any] = Field(default_factory=dict)
    sensitive: list[SensitiveItem] = Field(default_factory=list)
    source_kind: str  # mcp-log | debug-mirror | debug-file
    source: str  # file:line (first record)
    lines: list[int] = Field(default_factory=list)
    debug_copy: Optional[str] = None


class LogServerSummary(BaseModel):
    """Per (cwd, server folder) aggregation over MCP logs and debug-only records."""

    model_config = ConfigDict(extra="forbid")

    server: str
    server_dir: str
    encoded_cwd: Optional[str] = None
    cwds: list[str] = Field(default_factory=list)
    name_candidates: list[str] = Field(default_factory=list)
    name_status: str = "unknown"
    possibly_shared: bool = False  # a log file of this folder shows signs of several servers
    configured: bool = False
    log_files: list[str] = Field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    connect_attempts: int = 0
    connect_ok: int = 0
    connect_failed: int = 0
    connect_no_outcome: int = 0
    transports: list[str] = Field(default_factory=list)
    # remote server URLs of the connection attempts (transport records), as displayed: userinfo, query values
    # and fragment withheld unless --show-sensitive
    log_urls: list[str] = Field(default_factory=list)
    connect_ms_min: Optional[int] = None
    connect_ms_max: Optional[int] = None
    server_versions: list[str] = Field(default_factory=list)
    failure_codes: list[str] = Field(default_factory=list)
    tool_calls: int = 0
    tool_failed: int = 0
    tool_no_completion: int = 0
    error_records: int = 0
    stderr_records: int = 0
    shutdowns: int = 0
    sources: list[str] = Field(default_factory=list)  # mcp-log, debug-mirror


class CrossCheckItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str  # identical | redaction-only | error-object | differs from debug copy | mcp-log only | debug only
    server: str
    message_id: str
    mcp_log_source: Optional[str] = None
    debug_source: Optional[str] = None
    mcp_log_timestamp: Optional[str] = None
    debug_timestamp: Optional[str] = None
    offset_ms: Optional[int] = None  # MCP log ts - debug ts
    masked_in_debug: list[SensitiveItem] = Field(default_factory=list)
    text: Optional[str] = None  # withheld as usual
    debug_text: Optional[str] = None
    notes: list[str] = Field(default_factory=list)


class CrossCheck(BaseModel):
    """--debug mirror lines versus MCP-log records (where both exist)."""

    model_config = ConfigDict(extra="forbid")

    debug_files: int = 0
    mcp_log_records_in_scope: int = 0
    debug_mirror_lines: int = 0
    matched: int = 0
    identical: int = 0
    redaction_only: int = 0
    error_object: int = 0
    differs: int = 0
    mcp_log_only: int = 0
    debug_only: int = 0
    offset_histogram_ms: dict[str, int] = Field(default_factory=dict)
    offsets_outside_0_5ms: int = 0
    session_mismatches: int = 0
    order_inversions: int = 0
    items: list[CrossCheckItem] = Field(default_factory=list)  # every pair that is not "identical"
    context: list[str] = Field(default_factory=list)


Server.model_rebuild()
ToolCall.model_rebuild()
Case.model_rebuild()
