"""Parsers and the correlation/timeline engine.

This is the core of MCPeek. Every function here is written defensively
against the real, messy on-disk shapes observed in Claude Code artifacts:
polymorphic toolUseResult, ~10 non-message record types interleaved in a
transcript, two denial kinds, id-only (never tool-name) subagent linkage,
and absolute embedded paths that must be re-resolved against the --target root.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Optional

from . import safejson
from .loader import DiscoveredTarget, SessionFiles
from .models import (
    ClientIdKind,
    DebugServerInfo,
    DenialKind,
    Grant,
    OAuthClient,
    PathAlias,
    ProjectDir,
    Server,
    Session,
    SkippedSymlink,
    Subagent,
    Tool,
    ToolCall,
    Transport,
)
from .sensitive import scrub_credentials

# ---------------------------------------------------------------------------
# Tool name splitting: split on the FIRST "__" only, since either
# segment can itself contain underscores/hyphens (e.g.
# "mcp__claude_ai_Google_Drive__authenticate" -> server="claude_ai_Google_Drive").
# ---------------------------------------------------------------------------

_MCP_PREFIX = "mcp__"


def split_tool_name(name: Optional[str]) -> Optional[tuple[str, str]]:
    if not name or not name.startswith(_MCP_PREFIX):
        return None
    rest = name[len(_MCP_PREFIX) :]
    if "__" not in rest:
        return None
    server, tool = rest.split("__", 1)
    if not server or not tool:
        return None
    return server, tool


# ---------------------------------------------------------------------------
# JSONL loading: skip unknown record types, never assume a
# line has a "message" field.
# ---------------------------------------------------------------------------


def load_jsonl(path: Path, warnings: Optional[list[str]] = None) -> list[dict]:
    """Records of a transcript (see load_jsonl_lines)."""
    return [rec for _, rec in load_jsonl_lines(path, warnings)]


def load_jsonl_lines(path: Path, warnings: Optional[list[str]] = None) -> list[tuple[int, dict]]:
    """(line number, record) for each line of a transcript. A line that is not
    valid UTF-8 is decoded with replacement characters (and reported); a line
    that is not a JSON object is skipped (and reported). One bad line never
    drops the file."""
    records: list[tuple[int, dict]] = []
    if not path.is_file():
        return records
    bad_utf8: list[int] = []
    bad_json: list[int] = []
    try:
        f = open(path, "rb")
    except OSError as exc:
        if warnings is not None:
            warnings.append(f"{path} could not be read: {exc}")
        return records
    with f:
        for lineno, raw in enumerate(f, 1):
            line, replaced = safejson.decode(raw)
            if replaced:
                bad_utf8.append(lineno)
            line = line.strip()
            if not line:
                continue
            try:
                rec = safejson.loads(line)
            except ValueError:
                bad_json.append(lineno)
                continue
            if isinstance(rec, dict):
                records.append((lineno, rec))
            else:
                bad_json.append(lineno)
    if warnings is not None:
        if bad_utf8:
            warnings.append(f"{path}: line(s) {_line_list(bad_utf8)} not valid UTF-8 (decoded with replacement "
                            "characters)")
        if bad_json:
            warnings.append(f"{path}: line(s) {_line_list(bad_json)} not a JSON object (skipped)")
    return records


def _line_list(lines: list[int], limit: int = 10) -> str:
    shown = ", ".join(str(n) for n in lines[:limit])
    return shown + (f" and {len(lines) - limit} more" if len(lines) > limit else "")


class _FieldIssues:
    """Transcript fields with an unexpected JSON type, collected per field and
    reported once per file with the lines they occur on."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.issues: dict[tuple[str, str], list[int]] = {}

    def note(self, field: str, value: Any, line: int, action: str) -> None:
        self.issues.setdefault((f"{field} is {safejson.kind(value)}", action), []).append(line)

    def text(self, value: Any, field: str, line: int) -> Optional[str]:
        """A string field: other types are treated as absent (reported)."""
        if value is None or isinstance(value, str):
            return value
        self.note(field, value, line, "ignored")
        return None

    def ident(self, value: Any, field: str, line: int) -> Optional[str]:
        """An id field: a number is kept as its text, anything else that is not
        a non-empty string drops the block (both reported)."""
        if isinstance(value, str) and value:
            return value
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            self.note(field, value, line, "kept as text")
            return safejson.dumps(value)
        if value is not None and value != "":
            self.note(field, value, line, "block skipped")
        return None

    def flush(self, warnings: Optional[list[str]]) -> None:
        if warnings is None:
            return
        for (what, action), lines in sorted(self.issues.items()):
            warnings.append(f"{self.path}: {what} on line(s) {_line_list(sorted(set(lines)))} ({action})")


# ---------------------------------------------------------------------------
# toolUseResult polymorphism
# ---------------------------------------------------------------------------


def normalize_tool_use_result(raw: Any) -> Any:
    """toolUseResult is sometimes a dict, sometimes a JSON-encoded string,
    sometimes plain non-JSON text. Return whichever of these it actually is;
    never assume one shape.
    """
    if isinstance(raw, dict) or isinstance(raw, list):
        return raw
    if isinstance(raw, str):
        try:
            return safejson.loads(raw)
        except ValueError:
            return raw
    return raw


_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def classify_client_id(client_id: Optional[str]) -> ClientIdKind:
    if not client_id or not isinstance(client_id, str):
        return ClientIdKind.UNKNOWN
    if client_id.startswith("http://") or client_id.startswith("https://"):
        return ClientIdKind.CIMD
    if _UUID_RE.match(client_id):
        return ClientIdKind.DCR
    return ClientIdKind.UNKNOWN


# ---------------------------------------------------------------------------
# .claude.json -> Server entities
#
# Configuration files are read as found: a field of an unexpected type is
# coerced (a number or boolean where a string belongs is kept as its text) or
# skipped, and each case is reported as a warning naming file and field.
# ---------------------------------------------------------------------------


def _warn(warnings: Optional[list[str]], text: str) -> None:
    if warnings is not None:
        warnings.append(text)


_KNOWN_TRANSPORTS = {t.value for t in Transport if t is not Transport.UNKNOWN}


def known_transport(value: Any) -> Transport:
    """A transport name as the configuration or a log writes it: one of the
    known values, else unknown."""
    return Transport(value) if isinstance(value, str) and value in _KNOWN_TRANSPORTS else Transport.UNKNOWN


def _transport_of(cfg: dict, label: str, warnings: Optional[list[str]]) -> tuple[Transport, Optional[str]]:
    """The configured ``type`` and, when it is not a known transport, its
    text as written ("type": null is unknown with type_raw "null"). Without
    a ``type``: stdio with a command, http with a URL."""
    if "type" in cfg:
        t = cfg["type"]
        if not isinstance(t, str):
            _warn(warnings, f"{label}.type is {safejson.kind(t)}, not a string (kept as text)")
            return Transport.UNKNOWN, safejson.dumps(safejson.limit_depth(t))
        tr = known_transport(t)
        return tr, (t if tr is Transport.UNKNOWN else None)
    if "command" in cfg:
        return Transport.STDIO, None
    if "url" in cfg:
        return Transport.HTTP, None
    return Transport.UNKNOWN, None


def _text_list(value: Any, label: str, warnings: Optional[list[str]]) -> list[str]:
    """An array of strings (stdio args)."""
    if value is None:
        return []
    if isinstance(value, str):
        _warn(warnings, f"{label} is a string, not an array (kept as one argument)")
        return [value]
    if not isinstance(value, list):
        _warn(warnings, f"{label} is {safejson.kind(value)}, not an array (ignored)")
        return []
    out = []
    for i, v in enumerate(value):
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, (bool, int, float)):
            _warn(warnings, f"{label}[{i}] is {safejson.kind(v)}, not a string (shown as text)")
            out.append(safejson.dumps(v))
        else:
            _warn(warnings, f"{label}[{i}] is {safejson.kind(v)}, not a string (skipped)")
    return out


def _text_map(value: Any, label: str, warnings: Optional[list[str]]) -> dict[str, str]:
    """An object of string values (env, headers)."""
    obj = safejson.object_field(value, label, warnings)
    if obj is None:
        return {}
    out = {}
    for k, v in obj.items():
        if isinstance(v, str):
            out[k] = v
        elif isinstance(v, (bool, int, float)):
            _warn(warnings, f"{label}.{k} is {safejson.kind(v)}, not a string (shown as text)")
            out[k] = safejson.dumps(v)
        else:
            _warn(warnings, f"{label}.{k} is {safejson.kind(v)}, not a string (skipped)")
    return out


def _oauth_config(value: Any, label: str, warnings: Optional[list[str]]) -> Optional[dict[str, Any]]:
    """The configured ``oauth`` object of a server (clientId, callbackPort,
    authServerMetadataUrl, scopes, ...) as written: scalar values kept,
    nested values kept as JSON text (reported)."""
    obj = safejson.object_field(value, label, warnings)
    if obj is None:
        return None
    out: dict[str, Any] = {}
    for k, v in obj.items():
        if v is None or isinstance(v, (str, bool, int, float)):
            out[k] = v
        else:
            _warn(warnings, f"{label}.{k} is {safejson.kind(v)}, not a string or number (kept as JSON text)")
            out[k] = safejson.dumps(safejson.limit_depth(v))
    return out


def _server(name: str, cfg: Any, scope: str, path: Path, where: str,
            warnings: Optional[list[str]]) -> Optional[Server]:
    label = f"{path}: {where}"
    if not isinstance(cfg, dict):
        _warn(warnings, f"{label} is {safejson.kind(cfg)}, not an object (skipped)")
        return None
    transport, type_raw = _transport_of(cfg, label, warnings)
    return Server(
        name=name,
        scope=scope,
        transport=transport,
        type_raw=type_raw,
        command=safejson.text(cfg.get("command"), f"{label}.command", warnings),
        args=_text_list(cfg.get("args"), f"{label}.args", warnings),
        env=_text_map(cfg.get("env"), f"{label}.env", warnings),
        url=safejson.text(cfg.get("url"), f"{label}.url", warnings),
        headers=_text_map(cfg.get("headers"), f"{label}.headers", warnings),
        headers_helper=safejson.text(cfg.get("headersHelper"), f"{label}.headersHelper", warnings),
        oauth=_oauth_config(cfg.get("oauth"), f"{label}.oauth", warnings),
        source_path=str(path),
    )


def _servers_of(mcp_servers: Any, scope: str, path: Path, where: str,
                warnings: Optional[list[str]]) -> list[Server]:
    obj = safejson.object_field(mcp_servers, f"{path}: {where}", warnings)
    if obj is None:
        return []
    servers = []
    for name, cfg in obj.items():
        s = _server(name, cfg, scope, path, f"{where}.{name}", warnings)
        if s is not None:
            servers.append(s)
    return servers


def parse_user_config(path: Optional[Path], warnings: Optional[list[str]] = None) -> list[Server]:
    servers: list[Server] = []
    if path is None or not path.is_file():
        return servers
    # An existing-but-unparseable file is a materially different finding
    # from an absent one for a forensic examiner (corrupted/truncated/
    # edited vs. never configured) -- surface it rather than silently
    # collapsing both into an identical empty result.
    data = safejson.read_object(path, warnings)
    if data is None:
        return servers
    servers += _servers_of(data.get("mcpServers"), "user", path, "mcpServers", warnings)
    projects = safejson.object_field(data.get("projects"), f"{path}: projects", warnings)
    for proj_cwd, proj_cfg in (projects or {}).items():
        if not isinstance(proj_cfg, dict):
            _warn(warnings, f"{path}: projects.{proj_cwd} is {safejson.kind(proj_cfg)}, not an object (skipped)")
            continue
        servers += _servers_of(proj_cfg.get("mcpServers"), proj_cwd, path, f"projects.{proj_cwd}.mcpServers",
                               warnings)
    return servers


def parse_project_mcp_manifest(path: Path, project_cwd: str, warnings: Optional[list[str]] = None) -> list[Server]:
    """Parse a project-local .mcp.json; ``project_cwd`` is the project path on the examined host."""
    data = safejson.read_object(path, warnings)
    if data is None:
        return []
    return _servers_of(data.get("mcpServers"), project_cwd, path, "mcpServers", warnings)


# ---------------------------------------------------------------------------
# .credentials.json -> OAuthClient entities
# ---------------------------------------------------------------------------


def parse_credentials(path: Optional[Path], warnings: Optional[list[str]] = None) -> list[OAuthClient]:
    """MCP OAuth client registrations. Warnings name fields, never values."""
    clients: list[OAuthClient] = []
    if path is None or not path.is_file():
        return clients
    data = safejson.read_object(path, warnings)
    if data is None:
        return clients
    mcp_oauth = safejson.object_field(data.get("mcpOAuth"), f"{path}: mcpOAuth", warnings)
    for key, entry in (mcp_oauth or {}).items():
        label = f"{path}: mcpOAuth.{key}"
        if not isinstance(entry, dict):
            _warn(warnings, f"{label} is {safejson.kind(entry)}, not an object (skipped)")
            continue
        client_id = safejson.text(entry.get("clientId"), f"{label}.clientId", warnings)
        ds = safejson.object_field(entry.get("discoveryState"), f"{label}.discoveryState", warnings)
        clients.append(
            OAuthClient(
                key=key,
                server_name=safejson.text(entry.get("serverName"), f"{label}.serverName", warnings)
                or key.split("|", 1)[0],
                server_url=safejson.text(entry.get("serverUrl"), f"{label}.serverUrl", warnings),
                client_id=client_id,
                client_id_kind=classify_client_id(client_id),
                issuer=safejson.text(entry.get("issuer"), f"{label}.issuer", warnings),
                redirect_uri=safejson.text(entry.get("redirectUri"), f"{label}.redirectUri", warnings),
                discovery_state=scrub_credentials(safejson.limit_depth(ds)) if ds is not None else {},
                has_access_token=bool(entry.get("accessToken")),
                has_refresh_token=bool(entry.get("refreshToken")),
                source_path=str(path),
            )
        )
    return clients


# ---------------------------------------------------------------------------
# settings.local.json -> Grant entities
# ---------------------------------------------------------------------------

# Project .mcp.json server approvals: settings keys (also found in
# .claude.json project entries) -> grant kind
_MCPJSON_LISTS = {"enabledMcpjsonServers": "mcpjson-enabled", "disabledMcpjsonServers": "mcpjson-disabled"}
_MCPJSON_ALL = "enableAllProjectMcpServers"


def _mcpjson_approvals(obj: dict, scope: str, path: Path, where: str,
                       warnings: Optional[list[str]]) -> list[Grant]:
    out: list[Grant] = []
    for key, kind in _MCPJSON_LISTS.items():
        label = f"{where}.{key}" if where else key
        names = safejson.list_field(obj.get(key), f"{path}: {label}", warnings)
        for i, name in enumerate(names or []):
            if not isinstance(name, str):
                _warn(warnings, f"{path}: {label}[{i}] is {safejson.kind(name)}, not a string (skipped)")
                continue
            out.append(Grant(kind=kind, is_mcp=True, mcp_server=name, field=key, scope=scope, source_path=str(path)))
    if _MCPJSON_ALL in obj:
        label = f"{where}.{_MCPJSON_ALL}" if where else _MCPJSON_ALL
        value = obj[_MCPJSON_ALL]
        if isinstance(value, bool):
            out.append(Grant(kind="mcpjson-enable-all", value=value, field=_MCPJSON_ALL, scope=scope,
                             source_path=str(path)))
        elif value is not None:
            _warn(warnings, f"{path}: {label} is {safejson.kind(value)}, not a boolean (ignored)")
    return out


# The run-3, run-4 and run-8 interactive experiments (CLI 2.1.226) show the
# allow rule "mcp__*" rejected at settings load ("Invalid permission rule
# "mcp__*" was skipped: Wildcard tool name "mcp__*" is not supported in allow
# rules ... globs are permitted only in the tool position after a literal
# mcp__<server>__ prefix"). mcp__<server> and mcp__<server>__* were not
# reported as skipped.
_WILDCARD_ALL_NOTE = "wildcard over all MCP servers; reported in the experiments as skipped by CLI 2.1.226"
_WILDCARD_SERVER_NOTE = ("wildcard in the server name; not mapped to a server (CLI 2.1.226 allows globs only "
                         "after a literal mcp__<server>__ prefix and skipped \"mcp__*\" in the experiments)")


def parse_grants(path: Optional[Path], scope: str, warnings: Optional[list[str]] = None) -> list[Grant]:
    """``permissions.allow`` and the project .mcp.json server approvals of a
    settings.local.json."""
    grants: list[Grant] = []
    if path is None or not path.is_file():
        return grants
    data = safejson.read_object(path, warnings)
    if data is None:
        return grants
    permissions = safejson.object_field(data.get("permissions"), f"{path}: permissions", warnings) or {}
    allow = safejson.list_field(permissions.get("allow"), f"{path}: permissions.allow", warnings) or []
    for i, tool_name in enumerate(allow):
        if not isinstance(tool_name, str):
            _warn(warnings, f"{path}: permissions.allow[{i}] is {safejson.kind(tool_name)}, not a string (skipped)")
            continue
        split = split_tool_name(tool_name)
        if split is None and tool_name.startswith(_MCP_PREFIX) and "__" not in tool_name[len(_MCP_PREFIX):] \
                and len(tool_name) > len(_MCP_PREFIX):
            split = (tool_name[len(_MCP_PREFIX):], "*")  # mcp__<server>: every tool of the server
        note = None
        if split is not None and "*" in split[0]:
            # a wildcard in the server position is listed as written and not
            # mapped to any server (CLI 2.1.226 skips "mcp__*", see _WILDCARD_SERVER_NOTE)
            note = _WILDCARD_ALL_NOTE if tool_name == "mcp__*" else _WILDCARD_SERVER_NOTE
        grants.append(
            Grant(
                tool_name=tool_name,
                is_mcp=split is not None,
                mcp_server=split[0] if split and note is None else None,
                mcp_tool=split[1] if split and note is None else None,
                note=note,
                scope=scope,
                source_path=str(path),
            )
        )
    grants += _mcpjson_approvals(data, scope, path, "", warnings)
    return grants


def parse_config_approvals(path: Optional[Path], warnings: Optional[list[str]] = None) -> list[Grant]:
    """Project .mcp.json server approvals stored in .claude.json project
    entries (scope: the project path). The file is read again here; its
    parse problems are reported by parse_user_config."""
    if path is None or not path.is_file():
        return []
    data = safejson.read_object(path, None)
    projects = data.get("projects") if data is not None else None
    if not isinstance(projects, dict):
        return []
    out: list[Grant] = []
    for proj, cfg in projects.items():
        if isinstance(cfg, dict):
            out += _mcpjson_approvals(cfg, proj, path, f"projects.{proj}", warnings)
    return out


# ---------------------------------------------------------------------------
# Subagent discovery: agentId comes from the filename / the
# sidecar's own records, never from a field inside meta.json.
# ---------------------------------------------------------------------------

_META_RE = re.compile(r"^agent-(.+)\.meta\.json$")


def _spawn_depth(meta: dict, path: Path, warnings: Optional[list[str]]) -> Optional[int]:
    if "spawnDepth" not in meta:
        return 1
    value = meta["spawnDepth"]
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    _warn(warnings, f"{path}: spawnDepth is {safejson.kind(value)}, not an integer (depth shown as unknown)")
    return None


def discover_subagents(session_files: SessionFiles, warnings: Optional[list[str]] = None) -> list[Subagent]:
    subagents: list[Subagent] = []
    if session_files.subagent_dir is None:
        return subagents
    for meta_path in sorted(session_files.subagent_dir.glob("agent-*.meta.json")):
        m = _META_RE.match(meta_path.name)
        if not m or meta_path.name in session_files.skip_names:
            continue
        agent_id = m.group(1)
        meta = (safejson.read_object(meta_path, warnings) if meta_path.is_file() else None) or {}
        jsonl_path = session_files.subagent_dir / f"agent-{agent_id}.jsonl"
        label = str(meta_path) + ":"
        subagents.append(
            Subagent(
                agent_id=agent_id,
                agent_type=safejson.text(meta.get("agentType"), f"{label} agentType", warnings),
                description=safejson.text(meta.get("description"), f"{label} description", warnings),
                tool_use_id=safejson.text(meta.get("toolUseId"), f"{label} toolUseId", warnings) or "",
                spawn_depth=_spawn_depth(meta, meta_path, warnings),
                parent_agent_id=safejson.text(meta.get("parentAgentId"), f"{label} parentAgentId", warnings),
                session_uuid=session_files.session_uuid,
                sidecar_path=str(jsonl_path),
            )
        )
    return subagents


# ---------------------------------------------------------------------------
# Spill reference resolution: resolve the "tool-results/<basename>"
# (or the whole ".claude/projects/..." suffix) tail, never the literal
# embedded absolute path.
#
# Only the stub text the CLI writes in place of a spilled result is read
# (CLI 2.1.226: "Error: result (N characters) exceeds maximum allowed tokens.
# Output has been saved to <path>." for MCP results, and "<persisted-output>
# Output too large (N). Full output saved to: <path>" for other tools), and
# only when the result text starts with it. A path inside a tool's own
# result (e.g. the file.filePath of a native Read of a tool-results file, or
# a file whose content quotes a stub) is not a spill reference.
#
# Trailing sentence punctuation is stripped from captured paths so basenames
# match the real files on disk. A match is only treated as a genuine spill
# reference when "tool-results/" is actually a path segment in it (not an
# unrelated project-memory path).
#
# Containment: the reference comes from transcript text, so it can hold ".."
# segments, and a tool-results file can be a symlink. A reference that
# resolves outside the target root is reported ("OUTSIDE:<reference>") and
# never opened.
# ---------------------------------------------------------------------------

_SPILL_STUB_RE = re.compile(
    r"\A\s*(?:<persisted-output>\s*)?"
    r"(?:Error: result \([^)\n]{0,120}\) exceeds maximum allowed tokens\. Output has been saved to "
    r"|Output too large \([^)\n]{0,60}\)\. Full output saved to: )"
    r"(?P<path>[^\s\"'\\]+)")
_SPILL_PROJECTS_SUFFIX_RE = re.compile(r"\.claude/projects/([^\s\"'\\]+)")
_SPILL_BASENAME_RE = re.compile(r"tool-results/([^\s\"'\\]+)")
_TRAILING_PUNCT = ".,;:!?\"')]}"


def _strip_trailing_punct(s: str) -> str:
    return s.rstrip(_TRAILING_PUNCT)


def _extract_spill_reference(text: str) -> Optional[tuple[Optional[str], str]]:
    """Return (full_suffix_after_.claude/projects/, basename) or None.

    Only the path of a CLI spill stub at the start of the text, and only
    when it actually contains a "tool-results/" segment, is treated as a
    genuine spill reference (see module note above)."""
    stub = _SPILL_STUB_RE.match(text)
    if stub is None:
        return None
    text = stub.group("path")
    m = _SPILL_PROJECTS_SUFFIX_RE.search(text)
    if m:
        suffix = _strip_trailing_punct(m.group(1))
        if "tool-results/" in suffix:
            basename = _strip_trailing_punct(suffix.rsplit("/", 1)[-1])
            return suffix, basename
    m2 = _SPILL_BASENAME_RE.search(text)
    if m2:
        return None, _strip_trailing_punct(m2.group(1))
    return None


def _structured_content_text(result: dict) -> Optional[str]:
    """The third of the three on-disk redundant result sinks
    (message.content, toolUseResult, mcpMeta.structuredContent). Returns
    the raw string form if mcpMeta.structuredContent is present, else None."""
    mcp_meta = result.get("mcpMeta")
    if not isinstance(mcp_meta, dict):
        return None
    sc = mcp_meta.get("structuredContent")
    if sc is None:
        return None
    return sc if isinstance(sc, str) else safejson.dumps(sc)


def _texts_from_result(result: dict) -> list[str]:
    """The result texts that can hold a CLI spill stub: a string
    toolUseResult, the text of its content blocks, the tool_result content
    and mcpMeta.structuredContent. A structured toolUseResult object is a
    tool's own result (e.g. a Read's file.filePath) and is not scanned."""
    texts: list[str] = []
    tur = result.get("toolUseResult")
    if isinstance(tur, str):
        texts.append(tur)
    elif isinstance(tur, list):
        for block in tur:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                texts.append(block["text"])
    content = result.get("content")
    if isinstance(content, str):
        texts.append(content)
    elif isinstance(content, list):
        for block in content:
            if isinstance(block, dict):
                if isinstance(block.get("text"), str):
                    texts.append(block["text"])
                if isinstance(block.get("content"), str):
                    texts.append(block["content"])
    sc_text = _structured_content_text(result)
    if sc_text is not None:
        texts.append(sc_text)
    return texts


def _inside(path: Path, root: Path) -> bool:
    try:
        real = Path(os.path.realpath(path))
        return real == root or real.is_relative_to(root)
    except (OSError, ValueError):
        return False


def resolve_spill_path(
    result: dict, target_root: Path, session_files: SessionFiles,
    warnings: Optional[list[str]] = None, where: str = "",
) -> Optional[str]:
    try:
        root = Path(os.path.realpath(target_root))
    except (OSError, ValueError):
        root = target_root
    for text in _texts_from_result(result):
        ref = _extract_spill_reference(text)
        if ref is None:
            continue
        suffix, basename = ref
        candidates: list[tuple[Path, str]] = []
        if suffix:
            candidates.append((target_root / ".claude" / "projects" / suffix, f".claude/projects/{suffix}"))
        if session_files.tool_results_dir is not None:
            candidates.append((session_files.tool_results_dir / basename, f"tool-results/{basename}"))
        outside: Optional[str] = None
        for cand, shown in candidates:
            if not _inside(cand, root):
                outside = outside or shown
                continue
            if cand.is_file():
                return str(cand)
        if outside is not None:
            _warn(warnings, f"{where or session_files.jsonl_path}: spilled result reference {outside!r} resolves "
                            "outside the target root (not resolved)")
            return f"OUTSIDE:{outside}"
        # Neither resolved on disk -- still report the reference for the
        # examiner, flagged as unresolved, rather than silently dropping it.
        return f"UNRESOLVED:tool-results/{basename}"
    return None


# ---------------------------------------------------------------------------
# tool_use / tool_result extraction from one transcript's records
#
# Calls are kept per tool_use block, not per id: an id that occurs twice in
# one transcript gives two calls, and each tool_result is paired with the
# nearest preceding unpaired tool_use of its id (reported as a warning).
# ---------------------------------------------------------------------------


def _content_blocks(message: Any) -> list[dict]:
    if not isinstance(message, dict):
        return []
    content = message.get("content")
    if isinstance(content, list):
        return [b for b in content if isinstance(b, dict)]
    return []


def extract_tool_uses(records: list[tuple[int, dict]], issues: Optional[_FieldIssues] = None) -> list[dict]:
    issues = issues or _FieldIssues(Path("-"))
    out: list[dict] = []
    for line, rec in records:
        if rec.get("type") != "assistant":
            continue
        for block in _content_blocks(rec.get("message")):
            if block.get("type") == "tool_use":
                tid = issues.ident(block.get("id"), "tool_use id", line)
                if not tid:
                    continue
                out.append({
                    "id": tid,
                    "line": line,
                    "name": issues.text(block.get("name"), "tool_use name", line),
                    "input": block.get("input"),
                    "timestamp": issues.text(rec.get("timestamp"), "timestamp", line),
                    "cwd": issues.text(rec.get("cwd"), "cwd", line),
                })
    return out


def extract_tool_results(records: list[tuple[int, dict]], issues: Optional[_FieldIssues] = None) -> list[dict]:
    issues = issues or _FieldIssues(Path("-"))
    out: list[dict] = []
    for line, rec in records:
        if rec.get("type") != "user":
            continue
        for block in _content_blocks(rec.get("message")):
            if block.get("type") == "tool_result":
                tid = issues.ident(block.get("tool_use_id"), "tool_result tool_use_id", line)
                if not tid:
                    continue
                is_error = block.get("is_error", False)
                if not isinstance(is_error, bool):
                    if is_error is not None:
                        issues.note("tool_result is_error", is_error, line, "read as true/false by its truth value")
                    is_error = bool(is_error)
                mcp_meta = rec.get("mcpMeta")
                out.append({
                    "id": tid,
                    "line": line,
                    "is_error": is_error,
                    "content": block.get("content"),
                    "toolUseResult": normalize_tool_use_result(rec.get("toolUseResult")),
                    # Third of the three on-disk "redundant result sinks"
                    # (message.content, toolUseResult, mcpMeta.structuredContent)
                    # -- see _structured_content_text / _texts_from_result.
                    "mcpMeta": mcp_meta if isinstance(mcp_meta, dict) else None,
                    "denial_kind": issues.text(rec.get("toolDenialKind"), "toolDenialKind", line),
                    "timestamp": issues.text(rec.get("timestamp"), "timestamp", line),
                    "cwd": issues.text(rec.get("cwd"), "cwd", line),
                })
    return out


def pair_results(uses: list[dict], results: list[dict], path: Path,
                 warnings: Optional[list[str]] = None) -> dict[int, dict]:
    """Pair tool_result blocks with tool_use blocks (index into uses -> result).
    Each result takes the nearest preceding unpaired tool_use of its id (or,
    if none precedes it, the first unpaired one). A repeated tool_use id is
    reported with its lines."""
    by_id: dict[str, list[int]] = {}
    for i, u in enumerate(uses):
        by_id.setdefault(u["id"], []).append(i)
    paired: dict[int, dict] = {}
    for r in sorted(results, key=lambda x: x["line"]):
        free = [i for i in by_id.get(r["id"], []) if i not in paired]
        before = [i for i in free if uses[i]["line"] < r["line"]]
        if before:
            paired[before[-1]] = r
        elif free:
            paired[free[0]] = r
        elif r["id"] in by_id:
            _warn(warnings, f"{path}: tool_result for tool_use id {r['id']!r} on line {r['line']} has no unpaired "
                            "tool_use left (not paired)")
    for tid, idxs in by_id.items():
        if len(idxs) > 1:
            lines = ", ".join(str(uses[i]["line"]) for i in idxs)
            _warn(warnings, f"{path}: tool_use id {tid!r} appears on lines {lines}; each is kept as its own call, "
                            "and each tool_result is paired with the nearest preceding unpaired tool_use of that id")
    return paired


def _summarize(value: Any, limit: int = 140) -> Optional[str]:
    if value is None:
        return None
    text = value if isinstance(value, str) else safejson.dumps(value, default=str)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


_KNOWN_DENIAL_KINDS = {k.value for k in DenialKind if k != DenialKind.OTHER}


def build_tool_calls(
    tool_uses: list[dict],
    tool_results: list[dict],
    *,
    session_uuid: str,
    is_sidechain: bool,
    agent_id: Optional[str],
    spawn_depth: Optional[int],
    spawn_lookup: dict[str, str],
    target_root: Path,
    session_files: SessionFiles,
    source_path: Optional[str] = None,
    warnings: Optional[list[str]] = None,
) -> list[ToolCall]:
    calls: list[ToolCall] = []
    path = Path(source_path) if source_path else session_files.jsonl_path
    paired = pair_results(tool_uses, tool_results, path, warnings)
    for i, tu in enumerate(tool_uses):
        tid = tu["id"]
        name = tu.get("name")
        split = split_tool_name(name)
        call = ToolCall(
            tool_use_id=tid,
            tool_name=name or "",
            is_mcp=split is not None,
            mcp_server=split[0] if split else None,
            mcp_tool=split[1] if split else None,
            timestamp=tu.get("timestamp"),
            session_uuid=session_uuid,
            cwd=tu.get("cwd"),
            is_sidechain=is_sidechain,
            agent_id=agent_id,
            spawn_depth=spawn_depth,
            input_summary=_summarize(tu.get("input")),
            source_path=source_path,
            source_line=tu["line"],
        )
        result = paired.get(i)
        if result is not None:
            call.result_found = True
            call.result_timestamp = result.get("timestamp")
            call.result_is_error = result.get("is_error", False)
            if result.get("content") is not None:
                summary_source = result.get("content")
            elif result.get("toolUseResult") is not None:
                summary_source = result.get("toolUseResult")
            else:
                summary_source = _structured_content_text(result)
            call.result_summary = _summarize(summary_source)
            dk = result.get("denial_kind")
            if dk:
                call.denied = True
                call.denial_kind = DenialKind(dk) if dk in _KNOWN_DENIAL_KINDS else DenialKind.OTHER
            spill = resolve_spill_path(result, target_root, session_files, warnings, f"{path}:{result['line']}")
            if spill:
                call.spill_path = spill
        if tid in spawn_lookup:
            call.is_spawn = True
            call.spawned_agent_id = spawn_lookup[tid]
        calls.append(call)
    return calls


# ---------------------------------------------------------------------------
# Full session parse: main transcript + recursive subagent sidecars
# ---------------------------------------------------------------------------


def recorded_session_id(records: list[tuple[int, dict]], path: Path, stem: str,
                        warnings: Optional[list[str]] = None) -> str:
    """The session id the transcript's records give (their "sessionId"),
    which is what the MCP logs and debug files are named after. The file
    name is only used when no record gives one. A file name that differs
    from the recorded id (a renamed copy) or records with several ids are
    reported; the file stays the source and its companion folder (sub-agents,
    tool-results) is still found by the file name."""
    ids: dict[str, int] = {}
    for _line, rec in records:
        sid = rec.get("sessionId")
        if isinstance(sid, str) and sid:
            ids[sid] = ids.get(sid, 0) + 1
    if not ids:
        return stem
    if len(ids) == 1:
        sid = next(iter(ids))
        if sid != stem:
            _warn(warnings, f"{path}: the records give session id {sid!r}, the file name {stem!r}; the session "
                            "is listed under the recorded id (source: this file)")
        return sid
    chosen = stem if stem in ids else max(ids, key=lambda k: ids[k])
    shown = ", ".join(f"{k!r} ({n} records)" for k, n in list(ids.items())[:5])
    more = f" and {len(ids) - 5} more" if len(ids) > 5 else ""
    _warn(warnings, f"{path}: the records give {len(ids)} different session ids: {shown}{more}; the whole file is "
                    f"listed under {chosen!r} (" + ("its file name" if chosen == stem else "the most frequent id")
                    + "), so calls recorded under another id are not joined with that id's MCP log and debug file")
    return chosen


def parse_session(
    session_files: SessionFiles, target_root: Path, warnings: Optional[list[str]] = None
) -> tuple[Session, list[ToolCall], list[Subagent]]:
    from .mcplog import ts_ms

    main_records = load_jsonl_lines(session_files.jsonl_path, warnings)
    session_id = recorded_session_id(main_records, session_files.jsonl_path, session_files.session_uuid, warnings)
    subagents = discover_subagents(session_files, warnings)
    for sub in subagents:
        sub.session_uuid = session_id
    spawn_lookup = {s.tool_use_id: s.agent_id for s in subagents if s.tool_use_id}

    all_calls: list[ToolCall] = []

    issues = _FieldIssues(session_files.jsonl_path)
    main_tu = extract_tool_uses(main_records, issues)
    main_tr = extract_tool_results(main_records, issues)
    all_calls.extend(
        build_tool_calls(
            main_tu,
            main_tr,
            session_uuid=session_id,
            is_sidechain=False,
            agent_id=None,
            spawn_depth=0,
            spawn_lookup=spawn_lookup,
            target_root=target_root,
            session_files=session_files,
            source_path=str(session_files.jsonl_path),
            warnings=warnings,
        )
    )

    # Recurse into every subagent sidecar: a depth-2 subagent's own
    # spawn call lives inside its depth-1 parent's sidecar transcript, so we
    # must parse *every* sidecar for tool_use/tool_result blocks, not just
    # the main transcript.
    for sub in subagents:
        sidecar_path = Path(sub.sidecar_path)
        sub_records = [] if sidecar_path.name in session_files.skip_names else load_jsonl_lines(sidecar_path, warnings)
        sub_issues = _FieldIssues(sidecar_path)
        sub_tu = extract_tool_uses(sub_records, sub_issues)
        sub_tr = extract_tool_results(sub_records, sub_issues)
        sub_issues.flush(warnings)
        all_calls.extend(
            build_tool_calls(
                sub_tu,
                sub_tr,
                session_uuid=session_id,
                is_sidechain=True,
                agent_id=sub.agent_id,
                spawn_depth=sub.spawn_depth,
                spawn_lookup=spawn_lookup,
                target_root=target_root,
                session_files=session_files,
                source_path=str(sidecar_path),
                warnings=warnings,
            )
        )

    # Session-level stats, from the main transcript's own records only
    # cwd comes from each record's own "cwd" field. First and last are
    # compared as points in time (timestamps with an offset are normalized).
    cwds: set[str] = set()
    first: Optional[tuple] = None
    last: Optional[tuple] = None
    version: Optional[str] = None
    message_count = 0
    for line, rec in main_records:
        if rec.get("type") not in ("user", "assistant"):
            continue
        message_count += 1
        cwd = issues.text(rec.get("cwd"), "cwd", line)
        if cwd:
            cwds.add(cwd)
        ts = issues.text(rec.get("timestamp"), "timestamp", line)
        if ts:
            ms = ts_ms(ts)
            key = (0, ms, ts) if ms is not None else (1, 0, ts)
            if first is None or key < first:
                first = key
            if last is None or key > last:
                last = key
        v = issues.text(rec.get("version"), "version", line)
        if v:
            version = v
    issues.flush(warnings)

    tool_call_count = len(all_calls)
    mcp_tool_call_count = sum(1 for c in all_calls if c.is_mcp)

    session = Session(
        session_uuid=session_id,
        project_dir_encoded=session_files.project_dir_encoded,
        transcript_path=str(session_files.jsonl_path),
        cwds=sorted(cwds),
        first_timestamp=first[2] if first else None,
        last_timestamp=last[2] if last else None,
        version=version,
        message_count=message_count,
        tool_call_count=tool_call_count,
        mcp_tool_call_count=mcp_tool_call_count,
        subagent_count=len(subagents),
        has_subagent_dir=session_files.subagent_dir is not None,
        has_tool_results_dir=session_files.tool_results_dir is not None,
    )
    return session, all_calls, subagents


def build_tools_index(tool_calls: list[ToolCall]) -> list[Tool]:
    index: dict[tuple[str, str], Tool] = {}
    for call in tool_calls:
        if not call.is_mcp or not call.mcp_server or not call.mcp_tool:
            continue
        key = (call.mcp_server, call.mcp_tool)
        if key not in index:
            index[key] = Tool(server_name=call.mcp_server, tool_name=call.mcp_tool)
        index[key].call_count += 1
        if call.session_uuid not in index[key].sessions:
            index[key].sessions.append(call.session_uuid)
    for t in index.values():
        t.sessions.sort()
    return sorted(index.values(), key=lambda t: (t.server_name, t.tool_name))


# ---------------------------------------------------------------------------
# Top-level case assembly
# ---------------------------------------------------------------------------


def build_case(discovered: DiscoveredTarget, show_sensitive: bool = False):
    """Assemble the case. ``show_sensitive`` decides whether values from the
    MCP log and the --debug file that can be secrets (connect-time stderr,
    header values, URL query values, tool error text, elicitation content)
    are included, or withheld and described by kind, size, hash prefix and
    source (default)."""
    from .logevidence import build_log_evidence
    from .mcplog import ts_ms
    from .models import Case  # local import: keep module import graph simple
    from .sensitive import SensitivePolicy

    warnings = list(discovered.warnings)

    servers = parse_user_config(discovered.user_config_path, warnings=warnings)
    # Project .mcp.json manifests: scope is the project path on the examined
    # host, source_path the file under the target root.
    for pf in discovered.project_mcp_manifest_paths:
        servers.extend(parse_project_mcp_manifest(pf.path, pf.project_path, warnings))

    oauth_clients = parse_credentials(discovered.credentials_path, warnings=warnings)

    # A project at HOME has HOME/.claude/settings.local.json as its project
    # file, which is also the user-scope file: listed once, with both scopes.
    user_scope = "user"
    if discovered.user_grants_projects:
        user_scope = "user + project " + ", ".join(discovered.user_grants_projects)
    grants = list(parse_grants(discovered.user_grants_path, scope=user_scope, warnings=warnings))
    for pf in discovered.project_grant_paths:
        grants.extend(parse_grants(pf.path, scope=pf.project_path, warnings=warnings))
    grants.extend(parse_config_approvals(discovered.user_config_path, warnings))

    sessions: list[Session] = []
    all_tool_calls: list[ToolCall] = []
    all_subagents: list[Subagent] = []
    flt = discovered.filter
    for sf in discovered.sessions:
        try:
            session, calls, subs = parse_session(sf, discovered.target_root, warnings)
        except Exception as exc:  # defensive: one bad session must not kill the run
            warnings.append(f"failed to parse session {sf.session_uuid}: {exc}")
            continue
        sessions.append(session)
        all_tool_calls.extend(calls)
        all_subagents.extend(subs)
    by_id: dict[str, list[str]] = {}
    for s in sessions:
        by_id.setdefault(s.session_uuid, []).append(s.transcript_path)
    for sid, paths in sorted(by_id.items()):
        if len(paths) > 1:
            warnings.append(f"session id {sid!r} is recorded in {len(paths)} transcripts ({', '.join(paths)}); "
                            "each is listed as its own session row and their calls share the id")
    if flt is not None:
        # the selected sessions are the ids the parsed transcripts are listed
        # under; their MCP-log and --debug files follow from them
        from .loader import plan_log_files

        flt.session_ids = sorted(by_id)
        flt.known_session_ids |= set(by_id)
        plan_log_files(discovered, set(by_id))

    policy = SensitivePolicy(show=show_sensitive)
    evidence = build_log_evidence(discovered, servers, sessions, all_tool_calls, policy)
    warnings.extend(evidence.warnings)
    # a timestamp that is not ISO 8601 with a zone cannot be ordered: such a row is listed after the timed ones
    for where, ts in ([(f"{c.source_path}" + (f":{c.source_line}" if c.source_line else ""), c.timestamp)
                       for c in all_tool_calls] + [(lc.source, lc.start_timestamp) for lc in evidence.log_calls]):
        if isinstance(ts, str) and ts and ts_ms(ts) is None:
            warnings.append(f"{where}: timestamp {ts!r} is not an ISO 8601 time with a zone; the row cannot be "
                            "ordered in time and is listed after the timed rows")

    # --debug capabilities lines -> Server.debug_info
    debug_by_name: dict[str, list[DebugServerInfo]] = {}
    for info in evidence.debug_server_infos:
        debug_by_name.setdefault(info.server_name, []).append(info)
    configured_names = {s.name for s in servers}
    for server in servers:
        if server.name in debug_by_name:
            server.debug_info = debug_by_name[server.name]

    # Servers seen in a --debug file or an MCP log but not in the current
    # configuration: listed as their own rows, labelled by source, so they are
    # never confused with a configured server.
    from .mcplog import enc

    def seen_in(debug: bool, logs: list) -> str:
        # the sources the row is actually known from: a --debug file (its
        # capabilities lines or its copy of MCP-log records) and/or an MCP log
        names = []
        if debug or any("debug-mirror" in ls.sources for ls in logs):
            names.append("--debug file")
        if any("mcp-log" in ls.sources or ls.log_files for ls in logs):
            names.append("MCP log")
        return "seen in " + (" and ".join(names) or "MCP log")

    for name, infos in debug_by_name.items():
        if name in configured_names:
            continue
        logs = [ls for ls in evidence.summaries if ls.server_dir == enc(name) and not ls.configured]
        for ls in logs:
            ls.configured = True  # shown on this row
        servers.append(
            Server(
                name=name,
                scope=f"(not in current config; {seen_in(True, logs)})",
                transport=known_transport(infos[-1].transport),
                source_path=infos[0].debug_log_path,
                debug_info=infos,
                log_info=logs,
            )
        )
        warnings.append(f"server {name!r} appears in a --debug file but not in the current configuration")
    for ls in evidence.summaries:
        if ls.configured:
            continue
        where = ", ".join(ls.cwds) or ls.encoded_cwd or "?"
        tr = next((t for t in ls.transports if t in _KNOWN_TRANSPORTS), None)
        servers.append(
            Server(
                name=ls.server,
                scope=f"(not in current config for this cwd; {seen_in(False, [ls])} for {where})",
                transport=known_transport(tr),
                source_path=(ls.log_files or ["-"])[0],
                log_info=[ls],
            )
        )

    tools = build_tools_index(all_tool_calls)
    _add_log_tool_counts(tools, evidence.log_calls, all_tool_calls)

    return Case(
        target_root=str(discovered.target_root),
        home=discovered.home,
        home_source=discovered.home_source,
        projects=[ProjectDir(path=d.path, sources=list(d.sources),
                             target_path=str(d.target_path) if d.target_path is not None else None,
                             in_target=d.in_target) for d in discovered.project_dirs],
        servers=servers,
        tools=tools,
        sessions=sessions,
        subagents=all_subagents,
        tool_calls=all_tool_calls,
        oauth_clients=oauth_clients,
        grants=grants,
        cache_roots=evidence.cache_roots,
        mcp_log_files=evidence.mcp_log_files,
        debug_files=evidence.debug_files,
        debug_latest_links=evidence.latest_links,
        log_servers=evidence.summaries,
        log_calls=evidence.log_calls,
        server_events=evidence.events,
        cross_check=evidence.cross_check,
        sensitive_values_shown=show_sensitive,
        skipped_symlinks=[SkippedSymlink(path=str(x.path), target=x.target, looked_up_as=x.looked_up_as)
                          for x in discovered.skipped_links],
        path_aliases=[PathAlias(path=str(x.path), target=x.target, same_as=str(x.same_as), looked_up_as=x.looked_up_as)
                      for x in discovered.aliases],
        warnings=warnings,
        filter=session_filter(flt, evidence.filtered_out) if flt is not None else None,
    )


def session_filter(flt, filtered_out=None, quick: bool = False):
    """The filter object of a case (or of `sessions --quick`, which reads no log)."""
    from .models import SessionFilter

    out = SessionFilter(
        session_values=list(flt.sessions), project_values=list(flt.projects), session_ids=list(flt.session_ids),
        project_dirs=list(flt.project_dirs), transcript_files_total=flt.transcript_files,
        transcript_files_selected=len(flt.transcript_paths), transcript_paths=[str(p) for p in flt.transcript_paths],
    )
    matching = ("--session matches the session id of a transcript's first records or its file name; every "
                "transcript listed under the same session id is selected; transcripts are counted by file name")
    if quick:
        out.notes.append(matching + "; session_ids are the ids the selected transcripts are listed under, from "
                         "their first and last records")
        return out
    out.mcp_log_files_total, out.mcp_log_files_kept = flt.mcp_log_files_total, flt.mcp_log_files_kept
    out.mcp_log_files_pairing_only = flt.mcp_log_files_pairing_only
    out.debug_files_total, out.debug_files_kept = flt.debug_files_total, flt.debug_files_kept
    out.debug_files_pairing_only = flt.debug_files_pairing_only
    out.filtered_out_by_file = list(filtered_out or [])
    out.log_calls_filtered_out = sum(f.log_calls for f in out.filtered_out_by_file)
    out.server_events_filtered_out = sum(f.server_events for f in out.filtered_out_by_file)
    out.records_filtered_out = sum(f.records for f in out.filtered_out_by_file)
    out.sensitive_items_filtered_out = sum(f.sensitive_items for f in out.filtered_out_by_file)
    out.notes += [
        matching + "; only the selected transcripts are parsed (of the others the first records are read)",
        "MCP-log files shown: those in which a selected session appears (the leading record that --continue "
        "writes counts with the session that follows it); in them, calls of other sessions and their "
        "session-bound events are left out and counted per file, server process events (connect, shutdown, "
        "session switch, ...) are kept",
        "--debug files shown: those named after a selected session or paired with records of one",
        "files marked pairing_only are read only so that --debug mirror lines pair with MCP-log records as in an "
        "unfiltered run; none of their rows or records is shown, only their path and counts here",
        "logs: only the records of the selected sessions and records without a session id (MCP logs), the "
        "entries of the selected sessions (debug files), and the withheld values in them; the cross-check counts "
        "the records of the selected sessions in scope and the mirror lines paired with them",
        "values of other sessions' records stay withheld, also with --show-sensitive: a row kept from such "
        "records (a server process event) shows them as withheld in its text and carries no item of them "
        "(sensitive_items counts them per file)",
        "configured servers, OAuth clients and grants are listed in full; servers not in the current "
        "configuration and the per-server MCP log summaries come from the files shown",
    ]
    return out


def _add_log_tool_counts(tools: list[Tool], log_calls, tool_calls: list[ToolCall]) -> None:
    """Count MCP-log calls per tool. A call joined to a transcript call counts
    under that call's server and tool. Any other call counts under the
    transcript tool whose sanitized server and tool names equal the log
    folder and logged tool, if exactly one does; a call in a folder shared by
    several server names counts on a row of its own for the folder, with the
    candidate names."""
    from .mcplog import enc

    exact = {(t.server_name, t.tool_name): t for t in tools}
    loose: dict[tuple[str, str], list[Tool]] = {}
    for t in tools:
        loose.setdefault((enc(t.server_name), enc(t.tool_name)), []).append(t)
    by_id = {(c.session_uuid, c.tool_use_id): c for c in tool_calls if c.is_mcp}
    folder_rows: dict[tuple[str, str], Tool] = {}
    for lc in log_calls:
        t = None
        if lc.join_status == "matched" and lc.tool_use_id:
            tc = by_id.get((lc.session_id or "", lc.tool_use_id))
            if tc is not None:
                t = exact.get((tc.mcp_server, tc.mcp_tool))
        if t is None and len(lc.server_candidates) > 1:
            key = (lc.server_dir, enc(lc.tool))
            t = folder_rows.get(key)
            if t is None:
                t = Tool(server_name=lc.server_dir, tool_name=lc.tool, log_folder=lc.server_dir,
                         server_candidates=sorted(lc.server_candidates))
                folder_rows[key] = t
                tools.append(t)
        if t is None:
            same = loose.get((lc.server_dir, enc(lc.tool)), [])
            t = same[0] if len(same) == 1 else exact.get((lc.server, lc.tool))
            if t is None:
                t = Tool(server_name=lc.server, tool_name=lc.tool)
                exact[(lc.server, lc.tool)] = t
                loose.setdefault((lc.server_dir, enc(lc.tool)), []).append(t)
                tools.append(t)
        t.log_call_count += 1
        if lc.outcome == "failed":
            t.log_failed_count += 1
        src = lc.source.rsplit(":", 1)[0]
        if src not in t.log_sources:
            t.log_sources.append(src)
    for t in tools:
        t.log_sources.sort()
    tools.sort(key=lambda t: (t.server_name, t.tool_name, t.log_folder or ""))
