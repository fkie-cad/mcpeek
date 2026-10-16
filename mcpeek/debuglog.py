"""--debug session file parser (Claude Code CLI 2.1.226).

Line layout: ``<ISO ts> [LEVEL] <message>`` with LEVEL in VERBOSE, DEBUG,
INFO, WARN, ERROR. Internal newlines are kept, so continuation lines have no
header; an entry ends at the next header line. Under --output-format
json|stream-json a multi-line message is JSON-encoded (the message part
starts with '"'). Files written by an Agent SDK host (sdk-<uuid>.txt) use
``<ISO ts> <message>`` without a level. The file is split on "\\n" only.

MCP-log records are mirrored as ``MCP server "<raw name>": <msg>`` (DEBUG)
and ``MCP server "<raw name>" <msg>`` (ERROR). They are classified with the
same catalog as the MCP log and analysed like an MCP-log stream. Other
MCP-relevant lines (tool dispatch with toolUseId, permission decisions,
config loading, the "Dropping log batch" writer failure, resume links) come
from the debug_file_lines catalog.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from . import safejson
from .loader import DebugPath
from .logcatalog import UNCLASSIFIED, Classification, classify_debug_line, classify_mirror_text
from .mcplog import Rec, as_int, enc, mask_rec, output_fields, reclassify_tool_error_texts, retry_links, ts_ms
from .models import DebugDispatch, DebugEntry, DebugFile, DebugServerInfo
from .sensitive import SensitivePolicy, apply_spans, spans_for_message

# The CLI writes UTC with "Z"; an ISO offset ("+02:00") is accepted as well.
_TS = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}(?:Z|[+-]\d{2}:\d{2})"
HEADER_RE = re.compile(
    r"^(?P<ts>" + _TS + r") \[(?P<level>VERBOSE|DEBUG|INFO|WARN|ERROR)\] (?P<msg>.*)$",
    re.S,
)
LEVELLESS_RE = re.compile(r"^(?P<ts>" + _TS + r") (?P<msg>(?!\[[A-Z]+\] ).*)$", re.S)
MIRROR_RE = re.compile(r'^MCP server "(?P<server>.+?)"(?P<sep>: | )(?P<text>.*)\Z', re.S)


@dataclass
class RawEntry:
    line: int
    end_line: int
    timestamp: Optional[str]
    ts: Optional[int]
    level: Optional[str]
    message: str
    json_encoded: bool = False


@dataclass
class DispatchLine:
    tool: str
    tool_use_id: str
    ts: Optional[int]
    timestamp: Optional[str]
    source: str
    permission_decision_ms: Optional[int]
    used: bool = False


@dataclass
class ParsedDebugFile:
    info: DebugFile
    mirror_recs: list[Rec] = field(default_factory=list)
    dispatch_starts: list[DispatchLine] = field(default_factory=list)
    dispatch_ends: dict[str, tuple[str, int, str]] = field(default_factory=dict)  # id -> (outcome, ms, source)
    catalog_entries: list[tuple[RawEntry, Classification]] = field(default_factory=list)
    server_infos: list[DebugServerInfo] = field(default_factory=list)
    entrypoint_mode: str = "unknown"
    process_start_lines: list[int] = field(default_factory=list)  # a file can hold segments of several processes


def split_entries(text: str, allow_levelless: bool) -> tuple[list[RawEntry], int, int]:
    """Return (entries, continuation line count, lines before the first header)."""
    lines = text.split("\n")
    if text.endswith("\n"):
        lines = lines[:-1]
    entries: list[RawEntry] = []
    cont = 0
    before = 0
    for i, line in enumerate(lines, 1):
        m = HEADER_RE.match(line)
        level: Optional[str] = None
        if m:
            level = m.group("level")
        elif allow_levelless:
            m = LEVELLESS_RE.match(line)
        if m:
            entries.append(RawEntry(i, i, m.group("ts"), ts_ms(m.group("ts")), level, m.group("msg")))
            continue
        if entries:
            entries[-1].message += "\n" + line
            entries[-1].end_line = i
            cont += 1
        else:
            before += 1
    for e in entries:
        if len(e.message) >= 2 and e.message.startswith('"') and e.message.endswith('"'):
            try:
                decoded = safejson.loads(e.message)
            except ValueError:
                decoded = None
            if isinstance(decoded, str):
                e.message = decoded.strip()
                e.json_encoded = True
    return entries, cont, before


def parse_debug_file(dp: DebugPath, policy: SensitivePolicy) -> ParsedDebugFile:
    spath = str(dp.path)
    info = DebugFile(path=spath, origin=dp.origin, name_kind=dp.name_kind, session_id=dp.session_id)
    if dp.session_id:
        info.session_id_source = "file name (rotated .1)" if dp.name_kind == "rotated" else "file name"
    out = ParsedDebugFile(info=info)
    try:
        data = dp.path.read_bytes()
    except OSError as exc:
        info.notes.append(f"could not be read: {exc}")
        return out
    info.size_bytes = len(data)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
        info.notes.append("file is not valid UTF-8 (decoded with replacement characters)")
    if b"\r" in data:
        info.notes.append("file contains CR characters (the CLI writes LF only)")
    entries, cont, before = split_entries(text, dp.allow_levelless)
    info.lines = text.count("\n") + (0 if text.endswith("\n") or not text else 1)
    info.entry_count = len(entries)
    info.continuation_lines = cont
    info.lines_before_first_header = before
    info.json_encoded_entries = sum(1 for e in entries if e.json_encoded)
    info.levels = dict(Counter(e.level or "(none)" for e in entries))
    if entries:
        info.first_timestamp = entries[0].timestamp
        info.last_timestamp = entries[-1].timestamp
    prev = None
    for e in entries:
        if e.ts is not None:
            if prev is not None and e.ts < prev:
                info.timestamp_decreases += 1
            prev = e.ts
    if info.timestamp_decreases:
        info.notes.append(
            f"{info.timestamp_decreases} header line(s) with a timestamp earlier than the previous entry "
            "(concurrent writers, or header-like text inside a multi-line message)"
        )
    if before:
        info.notes.append(f"{before} line(s) before the first header line (file starts mid-entry)")

    servers: list[str] = []
    runtime_arm: Optional[str] = None
    pending_connect: dict[str, tuple[Optional[str], Optional[int]]] = {}
    for e in entries:
        src = f"{spath}:{e.line}"
        m = MIRROR_RE.match(e.message)
        if m:
            server, sep, mtext = m.group("server"), m.group("sep"), m.group("text")
            key = "debug" if sep == ": " else "error"
            rec_notes: list[str] = []
            expected = "DEBUG" if key == "debug" else "ERROR"
            if e.level and e.level != expected:
                rec_notes.append(f"mirror line with level {e.level} (the CLI writes {expected} for this form)")
            if e.json_encoded:
                rec_notes.append("JSON-encoded line (--output-format json/stream-json)")
            cls = classify_mirror_text(key, mtext)
            if cls.first_word_masked:
                rec_notes.append("first word masked by the CLI's debug redactor (keyword in the server name)")
            rec = Rec(
                source_path=spath, line=e.line, key=key, message=mtext, timestamp=e.timestamp, ts=e.ts,
                session_id=dp.session_id, cwd=None, cls=cls, message_id=cls.id, category=cls.category,
                catalog_status=cls.status, server_dir=enc(server), stream=f"{spath}\x00{server}",
                source_kind="debug-mirror", raw_server=server, notes=rec_notes, level=e.level,
            )
            mask_rec(rec, policy)
            out.mirror_recs.append(rec)
            if server not in servers:
                servers.append(server)
            if cls.id == "conn.ok":
                f = cls.fields()
                pending_connect[server] = (f.get("transport"), as_int(f.get("connect_ms")))
            elif cls.id == "conn.caps":
                out.server_infos.append(_server_info(server, rec, pending_connect.pop(server, (None, None)),
                                                     runtime_arm, dp))
            continue
        c = classify_debug_line(e.level, e.message)
        if c.entry is None:
            continue
        out.catalog_entries.append((e, c))
        f = c.fields()
        cid = c.id
        if cid == "dbg.dispatch_start":
            out.dispatch_starts.append(DispatchLine(
                tool=f["tool"], tool_use_id=f["tool_use_id"], ts=e.ts, timestamp=e.timestamp, source=src,
                permission_decision_ms=as_int(f.get("permission_decision_ms"))))
        elif cid in ("dbg.dispatch_end", "dbg.dispatch_post_error"):
            out.dispatch_ends[f["tool_use_id"]] = (f.get("outcome", "post_error"), as_int(f.get("duration_ms")), src)
        elif cid == "dbg.permission_denied":
            info.permission_denials += 1
        elif cid == "dbg.runtime_arm":
            runtime_arm = f.get("arm")
            if runtime_arm and runtime_arm not in info.runtime_arms:
                info.runtime_arms.append(runtime_arm)
        elif cid == "dbg.process_start":
            info.process_starts += 1
            out.process_start_lines.append(e.line)
        elif cid == "dbg.uds_listening":
            if f.get("pid") and f["pid"] not in info.pids:
                info.pids.append(f["pid"])
        elif cid == "dbg.entrypoint":
            ep = f.get("entrypoint", "").strip()
            if ep and ep not in info.entrypoints:
                info.entrypoints.append(ep)
        elif cid == "dbg.resume_link":
            info.resumes_session = f.get("session_id")
        elif cid == "dbg.prior_unclean":
            if f.get("session_id") not in info.prior_unclean_sessions:
                info.prior_unclean_sessions.append(f.get("session_id"))
        elif cid == "dbg.log_batch_dropped":
            info.log_batches_dropped.append(f.get("path", ""))
    reclassify_by_stream(out.mirror_recs, policy)
    info.mirror_lines = len(out.mirror_recs)
    info.mirror_unclassified = sum(1 for r in out.mirror_recs if r.message_id == UNCLASSIFIED)
    info.servers = servers
    info.dispatch_starts = len(out.dispatch_starts)
    if "cli" in info.entrypoints and "sdk-cli" not in info.entrypoints:
        out.entrypoint_mode = "interactive"
    elif "sdk-cli" in info.entrypoints and "cli" not in info.entrypoints:
        out.entrypoint_mode = "headless-or-mcp-list"
    if info.process_starts == 0 and entries:
        info.notes.append("no 'MDM settings load completed' line: the file does not start with a process start "
                          "(resumed session appended, /debug enabled mid-session, or a /clear switch)")
    if info.log_batches_dropped:
        info.notes.append(f"{len(info.log_batches_dropped)} 'Dropping log batch for <path>' line(s): MCP-log writes "
                          "failed in this process")
    info.mcp_entries = _debug_entries(out, policy)
    info.sensitive_item_count = sum(len(x.sensitive) for x in info.mcp_entries)
    return out


def reclassify_by_stream(recs: list[Rec], policy: SensitivePolicy) -> None:
    streams: dict[str, list[Rec]] = {}
    for r in recs:
        streams.setdefault(r.stream, []).append(r)
    for rs in streams.values():
        reclassify_tool_error_texts(rs, policy)


def _server_info(server: str, rec: Rec, connect: tuple[Optional[str], Optional[int]], runtime_arm: Optional[str],
                 dp: DebugPath) -> DebugServerInfo:
    raw = rec.message[rec.message.find("{"):] if "{" in rec.message else ""
    try:
        caps = safejson.loads(raw)
    except ValueError:
        caps = {}
    if not isinstance(caps, dict):
        caps = {}
    sv = caps.get("serverVersion")
    return DebugServerInfo(
        server_name=server,
        negotiated_protocol_version=caps.get("negotiatedProtocolVersion") if isinstance(caps.get("negotiatedProtocolVersion"), str) else None,
        server_version_name=sv.get("name") if isinstance(sv, dict) and isinstance(sv.get("name"), str) else None,
        server_version_version=sv.get("version") if isinstance(sv, dict) and isinstance(sv.get("version"), str) else None,
        server_version_text=sv if isinstance(sv, str) else None,
        protocol_era=caps.get("protocolEra") if isinstance(caps.get("protocolEra"), str) else None,
        runtime_arm=runtime_arm,
        has_tools=caps.get("hasTools") if isinstance(caps.get("hasTools"), bool) else None,
        has_prompts=caps.get("hasPrompts") if isinstance(caps.get("hasPrompts"), bool) else None,
        has_resources=caps.get("hasResources") if isinstance(caps.get("hasResources"), bool) else None,
        transport=connect[0],
        connect_ms=connect[1],
        timestamp=rec.timestamp,
        debug_log_path=str(dp.path),
        debug_log_line=rec.line,
        source_session_uuid=dp.session_id,
    )


def _debug_entries(out: ParsedDebugFile, policy: SensitivePolicy) -> list[DebugEntry]:
    items: list[DebugEntry] = []
    for r in out.mirror_recs:
        items.append(DebugEntry(
            line=r.line, end_line=r.line, timestamp=r.timestamp, level=r.level, mirror=True, server=r.raw_server,
            message_id=r.message_id, category=r.category, catalog_status=r.catalog_status, text=r.display,
            fields=output_fields(r.cls, r.withheld), sensitive=r.sensitive, notes=list(r.notes),
        ))
    for e, c in out.catalog_entries:
        src = f"{out.info.path}:{e.line}"
        spans = spans_for_message(c.mask, e.message, c)
        display, sens = apply_spans(e.message, spans, src, policy)
        withheld = [] if policy.show else [(sp.start, sp.end) for sp in spans]
        items.append(DebugEntry(
            line=e.line, end_line=e.end_line, timestamp=e.timestamp, level=e.level, json_encoded=e.json_encoded,
            message_id=c.id, category=c.category, catalog_status=c.status, text=display,
            fields=output_fields(c, withheld), sensitive=sens,
        ))
    items.sort(key=lambda x: x.line)
    return items


def _dispatch_server_tool(d: DispatchLine) -> Optional[tuple[str, str]]:
    if not d.tool.startswith("mcp__"):
        return None
    rest = d.tool[len("mcp__"):]
    if "__" not in rest:
        return None
    srv, tl = rest.split("__", 1)
    return enc(srv), enc(tl)


def file_retry_links(parsed: ParsedDebugFile) -> dict[int, tuple[Rec, Rec]]:
    """Retry links (mcplog.retry_links) of every mirror stream of one debug
    file. A tool_dispatch_start of the same server and tool between the
    "Retrying tool" line and the next Calling line marks that Calling line as
    a new tool use, not the retry."""
    streams: dict[str, list[Rec]] = {}
    for r in parsed.mirror_recs:
        streams.setdefault(r.stream, []).append(r)
    out: dict[int, tuple[Rec, Rec]] = {}
    for recs in streams.values():
        sd = recs[0].server_dir
        sep = []
        for d in parsed.dispatch_starts:
            st = _dispatch_server_tool(d)
            line = d.source.rpartition(":")[2]
            if st is not None and st[0] == sd and line.isdigit():
                sep.append((int(line), st[1]))
        out.update(retry_links(recs, tuple(parsed.process_start_lines), tuple(sep)))
    return out


def pair_dispatch(parsed: ParsedDebugFile, retries: Optional[dict[int, tuple[Rec, Rec]]] = None) -> dict[int, DebugDispatch]:
    """Pair each '[Stall] tool_dispatch_start' with the next mirrored
    'Calling MCP tool' line of the same server and tool (FIFO, within 10 s).
    The Calling line of a retry after session recovery (``retries``) belongs
    to the dispatch of the first attempt and is skipped.
    Returns {mirror Calling line: DebugDispatch}."""
    out: dict[int, DebugDispatch] = {}
    starts = parsed.dispatch_starts
    retries = retries or {}
    for r in parsed.mirror_recs:
        if r.message_id != "tool.call" or id(r) in retries:
            continue
        tool = r.fields().get("tool", "")
        for d in starts:
            if d.used or not d.tool.startswith("mcp__"):
                continue
            rest = d.tool[len("mcp__"):]
            if "__" not in rest:
                continue
            srv, tl = rest.split("__", 1)
            if enc(srv) != r.server_dir or enc(tl) != enc(tool):
                continue
            if d.ts is not None and r.ts is not None and not (0 <= r.ts - d.ts <= 10000):
                continue
            d.used = True
            end = parsed.dispatch_ends.get(d.tool_use_id)
            out[r.line] = DebugDispatch(
                tool=d.tool, tool_use_id=d.tool_use_id, permission_decision_ms=d.permission_decision_ms,
                outcome=end[0] if end else None, duration_ms=end[1] if end else None,
                start_source=d.source, end_source=end[2] if end else None,
            )
            break
    return out
