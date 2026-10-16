"""Per-server MCP log parser and the record analysis shared with the
--debug mirror lines.

File layout (Claude Code CLI 2.1.226, see docs/log-formats.md):
``<cacheRoot>/claude-cli-nodejs/<enc(cwd)>/mcp-logs-<enc(server)>/<start>.jsonl``
with one JSON object per line:
``{"debug"|"error": <msg>, "timestamp", "sessionId", "cwd"}``.

Reading is line-by-line and never stops at a bad line: an invalid or
truncated line is kept as an "invalid" record and reported. Every message
is classified against the catalog (logcatalog); messages that match no
template are kept as "unclassified".

The analysis turns a record stream (one MCP-log file, or the mirror lines of
one server in one debug file) into tool calls (Calling -> completion, FIFO
per tool), connection attempts, shutdown groups and other server events. It
does not interpret anything: durations are reported as logged, with their
precision.
"""
from __future__ import annotations

import calendar
import re
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any, Optional

from . import safejson
from .logcatalog import UNCLASSIFIED, Classification, classify_mcp_message
from .models import (
    LogCall,
    LoggedDuration,
    McpLogFile,
    McpLogRecord,
    SensitiveItem,
    ServerEvent,
    SessionSwitch,
)
from .sensitive import SensitivePolicy, apply_spans, spans_for_message, withhold_text

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

_FILE_NAME_RE = re.compile(r"^(\d{4}-\d\d-\d\d)T(\d\d)-(\d\d)-(\d\d)-(\d{3})Z\.jsonl$")
_KNOWN_KEYS = {"debug", "error", "timestamp", "sessionId", "cwd"}


def _base36(n: int) -> str:
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    if n == 0:
        return "0"
    out = []
    while n:
        n, r = divmod(n, 36)
        out.append(digits[r])
    return "".join(reversed(out))


def enc(s: str) -> str:
    """The CLI's path sanitizer: every UTF-16 code unit that is not
    [A-Za-z0-9] becomes "-"; names longer than 200 get a hash suffix."""
    parts = []
    for ch in s:
        if ch.isascii() and ch.isalnum():
            parts.append(ch)
        else:
            parts.append("--" if ord(ch) > 0xFFFF else "-")
    e = "".join(parts)
    if len(e) <= 200:
        return e
    h = 0
    data = s.encode("utf-16-le", errors="surrogatepass")
    for i in range(0, len(data) - 1, 2):
        c = data[i] | (data[i + 1] << 8)
        h = ((h << 5) - h + c) & 0xFFFFFFFF
    if h >= 0x80000000:
        h -= 0x100000000
    return e[:200] + "-" + _base36(abs(h))


def hc(s: str) -> str:
    """Transcript tool-name component: [^a-zA-Z0-9_-] -> "_"."""
    return re.sub(r"[^a-zA-Z0-9_-]", "_", s)


_ISO_TS_RE = re.compile(
    r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?(?:([Zz])|([+-])(\d\d):?(\d\d))$"
)


def ts_ms(s: Any) -> Optional[int]:
    """Milliseconds since the epoch (UTC) of an ISO 8601 timestamp with "Z" or
    an offset ("+02:00"); None for anything else (no zone, no timestamp)."""
    if not isinstance(s, str):
        return None
    m = _ISO_TS_RE.match(s)
    if not m:
        return None
    y, mo, d, h, mi, sec = (int(m.group(i)) for i in range(1, 7))
    if not (1 <= mo <= 12 and 1 <= d <= 31 and h <= 23 and mi <= 59 and sec <= 60):
        return None
    try:
        days = calendar.timegm((y, mo, d, 0, 0, 0, 0, 0, 0)) // 86400
    except (ValueError, OverflowError):
        return None
    if d > calendar.monthrange(y, mo)[1]:
        return None
    ms = ((days * 24 + h) * 60 + mi) * 60_000 + sec * 1000 + int(((m.group(7) or "") + "000")[:3])
    if m.group(9):
        offset = (int(m.group(10)) * 60 + int(m.group(11))) * 60_000
        ms -= offset if m.group(9) == "+" else -offset
    return ms


def as_int(text: Any) -> Optional[int]:
    """Integer value of a number field taken from a log line, or None if it
    is missing or implausibly long (more than 18 digits)."""
    if not isinstance(text, str) or not text.isdigit() or len(text) > 18:
        return None
    return int(text)


def file_name_time(name: str) -> Optional[str]:
    m = _FILE_NAME_RE.match(name)
    if not m:
        return None
    return f"{m.group(1)}T{m.group(2)}:{m.group(3)}:{m.group(4)}.{m.group(5)}Z"


_DUR_RE = re.compile(r"^(?:(?P<ms>\d+)ms|(?P<s>\d+)s|(?P<m>\d+)m (?P<ms_s>\d+)s)$")


def parse_duration(text: Optional[str]) -> Optional[LoggedDuration]:
    """'15ms' (exact), '3s' (3000-3999 ms, floored), '1m 5s' (65000-65999)."""
    if not text:
        return None
    m = _DUR_RE.match(text.strip())
    if not m:
        return None
    if any(g is not None and as_int(g) is None for g in m.groups()):
        return None
    if m.group("ms") is not None:
        v = int(m.group("ms"))
        return LoggedDuration(text=text, unit="ms", min_ms=v, max_ms=v, exact=True)
    if m.group("s") is not None:
        v = int(m.group("s")) * 1000
        return LoggedDuration(text=text, unit="s", min_ms=v, max_ms=v + 999, exact=False)
    v = int(m.group("m")) * 60000 + int(m.group("ms_s")) * 1000
    return LoggedDuration(text=text, unit="m s", min_ms=v, max_ms=v + 999, exact=False)


def seconds_duration(seconds: str) -> Optional[LoggedDuration]:
    n = as_int(seconds)
    if n is None:
        return None
    v = n * 1000
    return LoggedDuration(text=f"{seconds}s", unit="s", min_ms=v, max_ms=v + 999, exact=False)


def format_duration(d: Optional[LoggedDuration]) -> str:
    if d is None:
        return "-"
    if d.exact:
        return d.text
    return f"{d.text} ({d.min_ms}-{d.max_ms} ms)"


def _short(text: Optional[str], limit: int = 160) -> str:
    if not text:
        return ""
    t = " ".join(text.split())
    return t if len(t) <= limit else t[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# Internal record representation (raw message kept for analysis only)
# ---------------------------------------------------------------------------


@dataclass
class Rec:
    source_path: str
    line: int
    key: str  # debug | error | invalid
    message: str
    timestamp: Optional[str]
    ts: Optional[int]
    session_id: Optional[str]
    cwd: Optional[str]
    cls: Classification
    message_id: str
    category: str
    catalog_status: str
    server_dir: str
    stream: str
    source_kind: str  # mcp-log | debug-mirror
    raw_server: Optional[str] = None
    display: str = ""
    sensitive: list[SensitiveItem] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    xref: Optional["Rec"] = None  # counterpart in the other source (cross-check)
    xref_status: Optional[str] = None
    level: Optional[str] = None  # debug-mirror only
    withheld: list[tuple[int, int]] = field(default_factory=list)  # spans of message withheld on output
    error_text_of: Optional[int] = None  # line of the "failed after" record this error text belongs to

    @property
    def source(self) -> str:
        return f"{self.source_path}:{self.line}"

    def fields(self) -> dict[str, str]:
        return self.cls.fields()


def mask_rec(rec: Rec, policy: SensitivePolicy) -> None:
    spans = spans_for_message(rec.cls.mask, rec.message, rec.cls if rec.cls.entry else None, rec.message_id, rec.key)
    rec.display, rec.sensitive = apply_spans(rec.message, spans, rec.source, policy)
    rec.withheld = [] if policy.show else [(sp.start, sp.end) for sp in spans]


# Groups whose value is free text: carried by the (masked) record text only.
TEXT_GROUPS = frozenset({"stderr", "message", "json", "content", "detail", "url", "rules"})


def output_fields(cls: Classification, withheld: list[tuple[int, int]]) -> dict[str, Any]:
    """Fields of a classified message for output. Free-text groups are left
    to the masked text; any other field that overlaps a withheld span (for
    example a URI or reason holding a URL query value) is left out too."""
    out: dict[str, Any] = {}
    for k, v in cls.fields().items():
        if k in TEXT_GROUPS:
            continue
        sp = cls.span(k)
        if sp and any(sp[0] < e and s < sp[1] for s, e in withheld):
            continue
        out[k] = v
    return out


# Error records whose text is free-form (no template of their own).
_FREE_ERROR_IDS = {UNCLASSIFIED, "conn.error_object", "conn.error_stack"}


def _as_tool_error_text(r: Rec, policy: SensitivePolicy, note: str) -> None:
    r.message_id = "tool.error_text"
    r.category = "tool"
    r.catalog_status = "observed"
    r.notes.append(note)
    mask_rec(r, policy)


def reclassify_tool_error_texts(recs: list[Rec], policy: SensitivePolicy) -> None:
    """Tool error text in one record stream.

    An error record followed (within a few records) by "Tool 'T' failed after
    Ns: <same text>" is the tool's error text, whatever template the text
    happens to look like (an error stack, "Connection failed: ...").
    Free error text (no template, or an error object or stack) written while
    a tool call of the stream is in flight is treated as tool error text too.
    Both are withheld like the "failed after" text."""
    in_flight = 0
    for i, r in enumerate(recs):
        mid = r.message_id
        if mid == "tool.call":
            in_flight += 1
            continue
        if mid in ("tool.done", "tool.failed"):
            in_flight = max(0, in_flight - 1)
            continue
        if r.key != "error" or mid == "tool.error_text":
            continue
        text = r.message.strip()
        nxt = next((n for n in recs[i + 1: i + 4]
                    if n.message_id == "tool.failed" and n.fields().get("message", "").strip() == text), None)
        if nxt is not None and text:
            _as_tool_error_text(r, policy, f"error text of the tool call that fails at line {nxt.line}")
            r.error_text_of = nxt.line
        elif in_flight and mid in _FREE_ERROR_IDS:
            _as_tool_error_text(r, policy, "error record written while a tool call was in flight; treated as tool "
                                           "error text")


# ---------------------------------------------------------------------------
# Reading one MCP-log file
# ---------------------------------------------------------------------------


def read_mcp_log(path, *, cache_root: str, encoded_cwd: str, server_dir: str, server: str,
                 name_candidates: list[str], name_status: str,
                 policy: SensitivePolicy) -> tuple[McpLogFile, list[Rec]]:
    spath = str(path)
    info = McpLogFile(
        path=spath,
        cache_root=cache_root,
        encoded_cwd=encoded_cwd,
        server_dir=server_dir,
        server=server,
        name_candidates=name_candidates,
        name_status=name_status,
        file_name_time=file_name_time(path.name),
    )
    info.file_name_conforms = info.file_name_time is not None
    if not info.file_name_conforms:
        info.notes.append("file name is not <ISO time with - separators>.jsonl as the CLI writes it")
    try:
        data = path.read_bytes()
    except OSError as exc:
        info.notes.append(f"could not be read: {exc}")
        return info, []
    info.size_bytes = len(data)
    if not data:
        info.notes.append("empty file (0 bytes)")
        return info, []
    chunks = data.split(b"\n")
    if data.endswith(b"\n"):
        chunks = chunks[:-1]
    else:
        info.unterminated_last_line = True
        info.notes.append("last line has no newline terminator (truncated or still being written)")
    info.lines = len(chunks)

    recs: list[Rec] = []
    extra_keys: set[str] = set()
    for lineno, raw in enumerate(chunks, 1):
        if not raw.strip():
            info.empty_lines += 1
            continue
        notes: list[str] = []
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
            notes.append("line is not valid UTF-8 (decoded with replacement characters)")
        obj: Any = None
        try:
            obj = safejson.loads(text)
        except ValueError:
            obj = None
        key = None
        message = text
        if isinstance(obj, dict):
            if isinstance(obj.get("debug"), (str, int, float, bool, list, dict)) and "debug" in obj:
                key = "debug"
            elif "error" in obj:
                key = "error"
            if "debug" in obj and "error" in obj:
                notes.append("record has both 'debug' and 'error' keys; 'debug' used")
            if key is None:
                notes.append("record has neither 'debug' nor 'error' key")
            else:
                message = obj[key]
                if not isinstance(message, str):
                    message = safejson.dumps(message)
                    notes.append(f"'{key}' value is not a string")
            ek = set(obj) - _KNOWN_KEYS
            if ek:
                extra_keys |= ek
                notes.append("unexpected keys: " + ", ".join(sorted(ek)))
        else:
            notes.append("line is not a JSON object" if obj is not None else "line is not valid JSON")
        if key is None:
            info.invalid_lines.append(lineno)
            rec = Rec(
                source_path=spath, line=lineno, key="invalid", message=text,
                timestamp=None, ts=None, session_id=None, cwd=None,
                cls=Classification(None, None), message_id="invalid", category="invalid",
                catalog_status="invalid", server_dir=server_dir, stream=spath, source_kind="mcp-log",
                notes=notes,
            )
            if isinstance(obj, dict):
                rec.timestamp = obj.get("timestamp") if isinstance(obj.get("timestamp"), str) else None
                rec.ts = ts_ms(rec.timestamp)
                rec.session_id = obj.get("sessionId") if isinstance(obj.get("sessionId"), str) else None
            mask_rec(rec, policy)
            recs.append(rec)
            continue
        cls = classify_mcp_message(key, message)
        ts_text = obj.get("timestamp") if isinstance(obj.get("timestamp"), str) else None
        rec = Rec(
            source_path=spath, line=lineno, key=key, message=message,
            timestamp=ts_text, ts=ts_ms(ts_text),
            session_id=obj.get("sessionId") if isinstance(obj.get("sessionId"), str) else None,
            cwd=obj.get("cwd") if isinstance(obj.get("cwd"), str) else None,
            cls=cls, message_id=cls.id, category=cls.category, catalog_status=cls.status,
            server_dir=server_dir, stream=spath, source_kind="mcp-log", notes=notes,
        )
        if ts_text is None:
            rec.notes.append("missing or non-string timestamp")
        mask_rec(rec, policy)
        recs.append(rec)

    reclassify_tool_error_texts(recs, policy)
    info.extra_keys = sorted(extra_keys)
    summarize_file(info, recs)
    info.entries = [to_record_model(r) for r in recs]
    return info, recs


def to_record_model(r: Rec) -> McpLogRecord:
    return McpLogRecord(
        line=r.line, key=r.key, timestamp=r.timestamp, session_id=r.session_id, cwd=r.cwd,
        message_id=r.message_id, category=r.category, catalog_status=r.catalog_status,
        text=r.display, fields=output_fields(r.cls, r.withheld), sensitive=r.sensitive, notes=list(r.notes),
    )


def _mode_markers(recs: list[Rec]) -> tuple[list[str], str]:
    markers: list[str] = []
    interactive = headless = False
    ids = Counter(r.message_id for r in recs)
    if ids.get("chan.skipped") or ids.get("chan.registered"):
        markers.append("'Channel notifications' record (written by the interactive TUI)")
        interactive = True
    for r in recs:
        if r.message_id == "http.options":
            m = re.search(r'"User-Agent":"([^"]*)"', r.message)
            if m:
                ua = m.group(1)
                markers.append(f"User-Agent {ua}")
                if ua.endswith("(cli)"):
                    interactive = True
                elif "(sdk-cli)" in ua:
                    headless = True
    if ids.get("xport.closed") and ids.get("xport.cache_cleared"):
        markers.append("'connection closed' + 'Cleared connection cache' shutdown tail (headless or mcp list/get)")
        headless = True
    if interactive and not headless:
        return markers, "interactive"
    if headless and not interactive:
        return markers, "headless-or-mcp-list"
    return markers, "unknown"


def summarize_file(info: McpLogFile, recs: list[Rec]) -> None:
    good = [r for r in recs if r.key != "invalid"]
    info.record_count = len(recs)
    info.unclassified = sum(1 for r in recs if r.message_id in (UNCLASSIFIED, "invalid"))
    info.classified = info.record_count - info.unclassified
    info.counts_by_message = dict(sorted(Counter(r.message_id for r in recs).items()))
    tss = [r.timestamp for r in good if r.timestamp]
    if tss:
        info.first_timestamp, info.last_timestamp = tss[0], tss[-1]
    prev = None
    for r in good:
        if r.ts is not None:
            if prev is not None and r.ts < prev:
                info.timestamp_decreases += 1
            prev = r.ts
    seen: list[str] = []
    for r in good:
        if r.session_id and r.session_id not in seen:
            seen.append(r.session_id)
    info.session_ids = seen
    info.cwds = sorted({r.cwd for r in good if r.cwd})
    # session switches; a leading single record with an id used nowhere else
    sid_counts = Counter(r.session_id for r in good if r.session_id)
    if len(good) >= 2 and good[0].session_id and good[1].session_id and good[0].session_id != good[1].session_id \
            and sid_counts[good[0].session_id] == 1:
        info.leading_single_record_session = good[0].session_id
        info.notes.append(
            f"line {good[0].line} carries session id {good[0].session_id}, which appears on no other line of this "
            "file (the pattern written by --continue)"
        )
    for a, b in zip(good, good[1:]):
        if a.session_id != b.session_id and not (a is good[0] and info.leading_single_record_session):
            info.session_switches.append(
                SessionSwitch(line=b.line, timestamp=b.timestamp, from_session=a.session_id, to_session=b.session_id)
            )
    info.process_markers, info.mode = _mode_markers(recs)
    info.tool_calls = sum(1 for r in recs if r.message_id == "tool.call")
    info.shutdown_records = sum(1 for r in recs if r.category == "shutdown")
    info.sensitive_item_count = sum(len(r.sensitive) for r in recs)
    if info.unclassified:
        info.notes.append(f"{info.unclassified} record(s) unclassified or invalid (kept, see `mcpeek logs --records`)")


# ---------------------------------------------------------------------------
# Stream analysis: calls, connection attempts, shutdowns, other events
# ---------------------------------------------------------------------------


@dataclass
class StreamInfo:
    server: str
    server_dir: str
    candidates: list[str]
    source_kind: str
    mode: str = "unknown"
    cwd_hint: Optional[str] = None
    session_hint: Optional[str] = None
    process_starts: tuple[int, ...] = ()  # debug file: lines where a process starts
    # {id(Calling record of a retry): (Retrying record, failure record of the
    # first attempt)}; computed from the stream when None (see retry_links)
    retry_links: Optional[dict[int, tuple[Rec, Rec]]] = None


@dataclass
class BuiltCall:
    model: LogCall
    start: Rec
    end: Optional[Rec] = None
    start_ms: Optional[int] = None
    end_ms: Optional[int] = None
    # a call retried after session recovery: the first attempt's completion
    # record, the "Retrying tool" record and the retry's Calling record
    first_end: Optional[Rec] = None
    retrying: Optional[Rec] = None
    retry_start: Optional[Rec] = None


# ---------------------------------------------------------------------------
# Retry after session recovery
# ---------------------------------------------------------------------------

# When a tool call fails because the server no longer knows the MCP session,
# the CLI reconnects and calls the tool once more inside the same tool use:
#   Calling MCP tool: T / Tool 'T' failed after Ns: ... /
#   Retrying tool 'T' after session recovery / Calling MCP tool: T /
#   Tool 'T' completed successfully in Nms (or failed after Ns)
# Only the "Retrying tool" record links two Calling records; two calls of
# the same tool are never merged on timing alone.
RETRY_AFTER_FAILURE_MS = 10_000  # failure record -> Retrying record (written right after the failure)
RETRY_CALL_WINDOW_MS = 120_000  # Retrying record -> the retry's Calling record (after the reconnect)


def _gap_ok(a: Rec, b: Rec, limit_ms: int) -> bool:
    return a.ts is None or b.ts is None or 0 <= b.ts - a.ts <= limit_ms


def retry_links(recs: list[Rec], process_starts: tuple[int, ...] = (),
                separate_dispatch: tuple[tuple[int, str], ...] = ()) -> dict[int, tuple[Rec, Rec]]:
    """Calling records of one stream that retry an earlier, failed call of
    the same tool: {id(retry Calling record): (Retrying record, failure
    record of the first attempt)}.

    A "Retrying tool 'T' after session recovery" record is paired with the
    most recent failure of T before it (within RETRY_AFTER_FAILURE_MS), and
    with the next Calling record of T after it (within RETRY_CALL_WINDOW_MS).
    No link is made across a process start, when a connection attempt fails
    in between (the reconnect failed and the CLI does not call again), or
    when a '[Stall] tool_dispatch_start' of T (a new tool use; debug files
    only, given as (line, enc(tool)) in separate_dispatch) lies between the
    Retrying record and the Calling record."""
    failures: dict[str, list[Rec]] = {}
    waiting: dict[str, tuple[Rec, Rec]] = {}
    out: dict[int, tuple[Rec, Rec]] = {}

    def crosses(a: Rec, b: Rec) -> bool:
        return any(a.line < ps <= b.line for ps in process_starts)

    for r in recs:
        mid = r.message_id
        if mid == "conn.fail":
            waiting.clear()
            continue
        if mid not in ("tool.call", "tool.failed", "tool.retry_after_recovery"):
            continue
        tool = r.fields().get("tool", "")
        if mid == "tool.failed":
            failures.setdefault(tool, []).append(r)
        elif mid == "tool.retry_after_recovery":
            lst = [f for f in failures.get(tool, []) if _gap_ok(f, r, RETRY_AFTER_FAILURE_MS) and not crosses(f, r)]
            if lst:
                f = lst[-1]
                failures[tool].remove(f)
                waiting[tool] = (r, f)
        else:
            w = waiting.pop(tool, None)
            if w is None:
                continue
            if not _gap_ok(w[0], r, RETRY_CALL_WINDOW_MS) or crosses(w[0], r):
                continue
            if any(w[0].line < line < r.line and t == enc(tool) for line, t in separate_dispatch):
                continue
            out[id(r)] = w
    return out


def _attempt_text(outcome: str, duration: Optional[LoggedDuration], end: Optional[Rec]) -> str:
    if end is None:
        return "no completion record"
    if outcome == "completed":
        return f"completed successfully in {duration.text if duration else '?'} (line {end.line})"
    return f"failed after {end.fields().get('seconds', '?')}s (line {end.line})"


def retry_dispatch_note(bc: BuiltCall) -> Optional[str]:
    """For a retried call with a debug-file dispatch: whether the
    tool_dispatch_start/_end lines of its toolUseId enclose both attempts
    (same debug file, compared by line)."""
    d = bc.model.dispatch
    if bc.retry_start is None or d is None:
        return None
    path, _, sline = d.start_source.rpartition(":")
    if path != bc.start.source_path or not sline.isdigit():
        return None
    last = bc.end or bc.retry_start
    head = f"toolUseId {d.tool_use_id}: tool_dispatch_start (line {sline}) precedes the first attempt"
    if d.end_source is None:
        return head + "; no tool_dispatch_end for this toolUseId"
    eline = d.end_source.rpartition(":")[2]
    if eline.isdigit() and int(eline) > last.line:
        return (head + f" and tool_dispatch_end (line {eline}, outcome={d.outcome}) follows the retry's "
                + ("completion" if bc.end is not None else "Calling") + " record: one dispatch for both attempts")
    return head + f"; tool_dispatch_end (line {eline}) precedes the retry's last record (line {last.line})"


@dataclass
class BuiltEvent:
    model: ServerEvent
    anchor: Rec
    recs: list[Rec]


_TRANSPORT_INIT = {"http.init": "http", "ws.init": "ws", "sse.init": "sse", "sse.ide": "sse-ide",
                   "proxy.init": "claudeai-proxy"}
_TRANSPORT_DETAIL = {"http.node", "http.env", "http.options", "http.created", "http.client_created", "http.testing",
                     "http.parsed", "http.loopback", "http.bad_url", "ws.options", "proxy.using", "proxy.created",
                     "proxy.stateless", "headers.helper"}
_SHUTDOWN_STEPS = {
    "proc.sigint": "SIGINT sent",
    "proc.sigterm": "SIGTERM sent",
    "proc.sigkill": "SIGKILL sent",
    "proc.exited": "process exited",
    "proc.cleanup_timeout": "cleanup timeout",
    "proc.error": "process-control error",
    "xport.cache_cleared": "connection cache cleared",
    "xport.terminal": "terminal connection error",
    "xport.closing": "closing transport",
    "xport.close_error": "error during close",
}
_SHUTDOWN_STRONG = {"proc.sigint", "proc.sigterm", "proc.sigkill", "proc.exited", "xport.closed", "xport.cache_cleared"}
# The shutdown tail of an interactive HTTP session (docs/log-formats.md 2.9):
# no "closed" record, only these steps, at the end of the process's records.
_INTERACTIVE_HTTP_TAIL = {"xport.dropped", "xport.conn_error", "xport.terminal"}
# Steps written once per server in a shutdown sequence. SIGINT and "exited
# cleanly" can repeat for one server (a call aborted at shutdown).
_ONCE_PER_SERVER = {"xport.closed", "xport.cache_cleared", "proc.sigterm"}
_EVENT_BY_CATEGORY = {
    "elicitation": "elicitation",
    "roots": "roots-request",
    "list-changed": "list-changed",
    "reconnect": "reconnect",
    "resource": "resource",
    "prompt": "prompt",
    "tool-schema": "tool-schema",
    "skills": "skills",
    "discovery-cache": "discovery-cache",
    "config": "config",
    "channel": "channel",
    "oauth": "oauth",
    "connection": "connection",
    "tool": "tool-note",
    "stderr": "stderr",
    "transport": "transport",
    "capabilities": "capabilities",
    UNCLASSIFIED: "unclassified",
    "invalid": "unparsed-line",
}


def _debug_named_server(info: StreamInfo, recs: list[Rec]) -> Optional[str]:
    """In a folder shared by several server names, the raw server name of a
    group of MCP-log records, if every record has a debug-file twin and the
    twins name one server."""
    names = {r.xref.raw_server if r.xref is not None else None for r in recs}
    if len(names) == 1 and None not in names:
        return names.pop()
    return None


def _event(info: StreamInfo, event: str, recs: list[Rec], summary: str, flds: dict[str, Any],
           sensitive: list[SensitiveItem], session: Optional[str] = None, server: Optional[str] = None) -> BuiltEvent:
    anchor = recs[0]
    last = recs[-1]
    if len(info.candidates) > 1 and info.source_kind == "mcp-log":
        # folder shared by several server names: the records name no server
        if server is None:
            server = _debug_named_server(info, recs)
        if server is not None:
            flds = dict(flds, server_from="debug-file mirror lines")
        else:
            flds = dict(flds, folder_shared_by=list(info.candidates))
    model = ServerEvent(
        event=event,
        timestamp=anchor.timestamp,
        end_timestamp=last.timestamp if last is not anchor else None,
        session_uuid=session if session is not None else (last.session_id or anchor.session_id or info.session_hint),
        cwd=anchor.cwd or info.cwd_hint,
        server=server or info.server,
        server_dir=info.server_dir,
        server_candidates=info.candidates,
        summary=summary,
        fields=flds,
        sensitive=sensitive,
        source_kind=info.source_kind,
        source=anchor.source,
        lines=[r.line for r in recs],
    )
    return BuiltEvent(model, anchor, recs)


class _Attempt:
    def __init__(self, rec: Rec, transport_hint: Optional[str] = None):
        self.recs: list[Rec] = [rec]
        self.started = transport_hint is None
        self.transport_hint = transport_hint
        self.outcome = "no outcome record"
        self.fields: dict[str, Any] = {}
        self.sensitive: list[SensitiveItem] = []
        self.awaiting_caps = False
        self.done = False

    def add(self, rec: Rec) -> None:
        self.recs.append(rec)
        self.sensitive.extend(rec.sensitive)


def _options_fields(rec: Rec) -> dict[str, Any]:
    """Header names (never values), auth-provider flag and timeout of a
    transport-options record."""
    out: dict[str, Any] = {}
    try:
        obj = safejson.loads(rec.message[rec.message.index("{"):])
    except ValueError:
        obj = None
    if isinstance(obj, dict):
        headers = obj.get("headers")
        if isinstance(headers, dict):
            out["header_names"] = list(headers.keys())
            ua = headers.get("User-Agent")
            if isinstance(ua, str):
                out["user_agent"] = ua
            out["headers_redacted_by_cli"] = [k for k, v in headers.items() if v == "[REDACTED]"]
        if "hasAuthProvider" in obj:
            out["has_auth_provider"] = safejson.limit_depth(obj.get("hasAuthProvider"))
        if "hasSessionAuth" in obj:
            out["has_session_auth"] = safejson.limit_depth(obj.get("hasSessionAuth"))
        if "timeoutMs" in obj:
            out["request_timeout_ms"] = safejson.limit_depth(obj.get("timeoutMs"))
    else:
        from .sensitive import header_spans

        out["header_names"] = [sp.field for sp in header_spans(rec.message) if sp.field]
        out["options_not_json"] = True  # e.g. the debug redactor swallowed a closing quote
    return out


def _caps_fields(rec: Rec) -> dict[str, Any]:
    out: dict[str, Any] = {}
    raw = rec.fields().get("json") or rec.message[rec.message.find("{"):]
    try:
        caps = safejson.loads(raw)
    except ValueError:
        out["capabilities_parse_error"] = True
        return out
    if not isinstance(caps, dict):
        return out
    sv = safejson.limit_depth(caps.get("serverVersion"))
    if isinstance(sv, dict):
        out["server_info"] = sv
        name, ver = sv.get("name"), sv.get("version")
        out["server_version"] = f"{name}/{ver}" if name or ver else safejson.dumps(sv)
    elif sv is not None:
        out["server_version"] = sv if isinstance(sv, str) else safejson.dumps(sv)
    out["capabilities"] = safejson.limit_depth({k: v for k, v in caps.items() if k != "serverVersion"})
    return out


def analyze_stream(recs: list[Rec], info: StreamInfo, policy: SensitivePolicy) -> tuple[list[BuiltCall], list[BuiltEvent]]:
    calls: list[BuiltCall] = []
    events: list[BuiltEvent] = []
    pending: dict[str, deque[BuiltCall]] = {}
    in_flight: list[BuiltCall] = []
    attempts: list[_Attempt] = []
    open_attempts: list[_Attempt] = []
    failed_recent: list[_Attempt] = []
    shutdown_group: list[Rec] = []
    shutdown_last_ts: Optional[int] = None
    shutdown_last_idx = 0

    def shutdown_event(g: list[Rec], server: Optional[str], shared: bool, at_end: bool) -> None:
        ids = [r.message_id for r in g]
        strong = any(i in _SHUTDOWN_STRONG for i in ids)
        steps: list[str] = []
        flds: dict[str, Any] = {"steps": ids}
        if (not strong and at_end and info.mode == "interactive" and set(ids) <= _INTERACTIVE_HTTP_TAIL
                and {"xport.dropped", "xport.terminal"} <= set(ids)):
            # the shutdown tail of an interactive HTTP session (docs/log-formats.md 2.9)
            strong = True
            flds["interactive_http_tail"] = True
        repeated = sorted(i for i, n in Counter(ids).items() if n > 1 and i in _ONCE_PER_SERVER)
        if repeated:
            flds["repeated_steps"] = repeated  # a sign of several servers in one file
        for r in g:
            f = r.fields()
            if r.message_id == "xport.closed":
                steps.append(f"{f.get('transport', '?')} connection closed after {f.get('uptime_s', '?')}s ({f.get('how', '?')})")
                flds.setdefault("transport", f.get("transport"))
                flds.setdefault("uptime_s", as_int(f.get("uptime_s")))
                flds.setdefault("closed", f.get("how"))
            elif r.message_id == "xport.dropped":
                steps.append(f"{f.get('transport', '?')} connection dropped after {f.get('uptime_s', '?')}s uptime")
                flds.setdefault("transport", f.get("transport"))
                flds.setdefault("uptime_s", as_int(f.get("uptime_s")))
            elif r.message_id in ("xport.conn_error", "xport.conn_error_errno"):
                text = r.display
                if text.lower().startswith("connection error: "):
                    text = text[len("connection error: "):]  # the record's own prefix, not repeated
                steps.append("connection error: " + _short(text, 100))
            else:
                steps.append(_SHUTDOWN_STEPS.get(r.message_id, r.message_id))
        dedup: list[str] = []
        for s in steps:
            if not dedup or dedup[-1] != s:
                dedup.append(s)
        name = "shutdown" if strong else "transport-error"
        head = name
        if shared:
            head += (" of every server sharing this MCP-log folder (" + ", ".join(info.candidates)
                     + "; the records name no server)")
        sens = [i for r in g for i in r.sensitive]
        events.append(_event(info, name, g, f"{head}: " + "; ".join(dedup), flds, sens, server=server))

    def flush_shutdown() -> None:
        nonlocal shutdown_group
        if not shutdown_group:
            return
        g = shutdown_group
        shutdown_group = []
        # no record of this stream follows, or the next one belongs to a later process
        nxt = recs[shutdown_last_idx + 1] if shutdown_last_idx + 1 < len(recs) else None
        at_end = nxt is None or any(g[-1].line < ps <= nxt.line for ps in info.process_starts)
        shared = len(info.candidates) > 1 and info.source_kind == "mcp-log"
        if shared:
            names = [r.xref.raw_server if r.xref is not None else None for r in g]
            if None not in names and len(set(names)) > 1:
                # every record has a debug-file twin that names its server
                for n in sorted(set(names), key=names.index):
                    shutdown_event([r for r, x in zip(g, names) if x == n], n, False, at_end)
                return
            if None not in names:
                shutdown_event(g, names[0], False, at_end)
                return
        shutdown_event(g, None, shared, at_end)

    def oldest_open() -> Optional[_Attempt]:
        for a in open_attempts:
            if not a.done:
                return a
        return None

    def finish(a: _Attempt, outcome: str) -> None:
        a.outcome = outcome
        a.done = True
        if a in open_attempts:
            open_attempts.remove(a)

    links = info.retry_links if info.retry_links is not None else retry_links(recs, info.process_starts)
    retried: list[BuiltCall] = []

    for idx, r in enumerate(recs):
        mid = r.message_id
        f = r.fields()

        # shutdown / transport-error grouping (records within 2 s of each other)
        if r.category == "shutdown":
            if shutdown_group and shutdown_last_ts is not None and r.ts is not None and r.ts - shutdown_last_ts > 2000:
                flush_shutdown()
            shutdown_group.append(r)
            shutdown_last_ts = r.ts if r.ts is not None else shutdown_last_ts
            shutdown_last_idx = idx
            continue

        # ---- tool calls ----
        if mid == "tool.call":
            tool = f.get("tool", "")
            same = pending.get(tool)
            link = links.get(id(r))
            first = next((b for b in reversed(calls) if b.end is link[1]), None) if link else None
            if first is not None and first.retry_start is None:
                # the CLI's retry of a call that failed: one logical call, the
                # last attempt gives outcome and completion
                lc = first.model
                first.first_end, first.retrying, first.retry_start = first.end, link[0], r
                first.end, first.end_ms = None, None
                lc.end_source = lc.end_timestamp = lc.timestamp_delta_ms = lc.duration = lc.error_text = None
                lc.outcome = "no completion record"
                if same:
                    lc.notes.append("another call of the same tool was in flight when the retry started")
                    for other in same:
                        other.model.completion_pairing = "fifo, same tool in flight (ambiguous)"
                    lc.completion_pairing = "fifo, same tool in flight (ambiguous)"
                pending.setdefault(tool, deque()).append(first)
                in_flight.append(first)
                retried.append(first)
                continue
            lc = LogCall(
                source_kind=info.source_kind, source=r.source, server=info.server, server_dir=info.server_dir,
                server_candidates=info.candidates, tool=tool, session_id=r.session_id, cwd=r.cwd or info.cwd_hint,
                start_timestamp=r.timestamp, outcome="no completion record", concurrent_calls=len(in_flight),
                process_mode=info.mode,
            )
            if same:
                lc.notes.append("another call of the same tool was in flight when this call started")
                for other in same:
                    other.model.completion_pairing = "fifo, same tool in flight (ambiguous)"
                lc.completion_pairing = "fifo, same tool in flight (ambiguous)"
            bc = BuiltCall(lc, r, start_ms=r.ts)
            pending.setdefault(tool, deque()).append(bc)
            in_flight.append(bc)
            calls.append(bc)
            continue
        if mid in ("tool.done", "tool.failed"):
            tool = f.get("tool", "")
            q = pending.get(tool)
            if q:
                bc = q.popleft()
                in_flight.remove(bc)
                lc = bc.model
                bc.end, bc.end_ms = r, r.ts
                lc.end_source = r.source
                lc.end_timestamp = r.timestamp
                if bc.start_ms is not None and r.ts is not None:
                    lc.timestamp_delta_ms = r.ts - bc.start_ms
                if mid == "tool.done":
                    lc.outcome = "completed"
                    lc.duration = parse_duration(f.get("duration"))
                else:
                    lc.outcome = "failed"
                    lc.duration = seconds_duration(f.get("seconds", "0"))
                    span = r.cls.span("message")
                    raw = r.message[span[0]:span[1]] if span else None
                    lc.error_text, items = withhold_text("tool-error-text", raw, r.source, policy)
                    lc.sensitive.extend(items)
            else:
                events.append(_event(info, "unpaired-completion", [r],
                                     f"completion record for tool '{tool}' without a preceding Calling record in this "
                                     "stream", {"tool": tool}, r.sensitive))
            continue
        if mid == "tool.running":
            tool = f.get("tool", "")
            q = pending.get(tool)
            if q:
                elapsed = as_int(f.get("elapsed_s"))
                if elapsed is not None:
                    q[0].model.heartbeats_s.append(elapsed)
            continue
        if mid == "tool.error_text" and r.error_text_of is not None:
            continue  # carried by the following "failed after" record

        # ---- connection attempts ----
        if mid in _TRANSPORT_INIT:
            a = _Attempt(r, _TRANSPORT_INIT[mid])
            if f.get("url"):
                a.fields["url"] = r.display.split(" to ", 1)[-1] if " to " in r.display else r.display
            a.sensitive.extend(r.sensitive)
            attempts.append(a)
            open_attempts.append(a)
            continue
        if mid in _TRANSPORT_DETAIL:
            target = open_attempts[-1] if open_attempts else None
            if target is not None:
                target.add(r)
                if mid in ("http.options", "ws.options"):
                    target.fields.update(_options_fields(r))
                elif mid == "http.parsed":
                    target.fields.update({"host": f.get("host"), "port": f.get("port"), "protocol": f.get("protocol")})
                elif mid == "http.node":
                    target.fields["runtime"] = f.get("node_version")
                elif mid == "http.env":
                    target.fields["environment_line"] = r.display
                elif mid == "proxy.using" and f.get("url"):
                    target.fields.setdefault("url", r.display.split(" at ", 1)[-1] if " at " in r.display
                                             else r.display)
                continue
        if mid == "conn.start":
            last = open_attempts[-1] if open_attempts else None
            if last is not None and not last.started:
                last.started = True
                last.add(r)
                last.fields["timeout_ms"] = as_int(f.get("timeout_ms"))
            else:
                a = _Attempt(r)
                a.fields["timeout_ms"] = as_int(f.get("timeout_ms"))
                if any(x.started and not x.done for x in open_attempts):
                    a.fields["overlaps_other_attempt"] = True
                attempts.append(a)
                open_attempts.append(a)
            continue
        if mid in ("conn.stderr", "conn.probe_stderr"):
            a = oldest_open()
            if a is not None:
                a.add(r)
                a.fields["stderr_records"] = a.fields.get("stderr_records", 0) + 1
            else:
                events.append(_event(info, "stderr", [r], "stderr record outside a connection attempt: "
                                     + _short(r.display, 120), {}, r.sensitive))
            continue
        if mid == "conn.ok":
            cands = [a for a in open_attempts if not a.done and a.started] or [a for a in open_attempts if not a.done]
            a = cands[0] if cands else None
            if a is None:
                a = _Attempt(r)
                attempts.append(a)
                a.fields["note"] = "connected record without a preceding start record"
            else:
                a.add(r)
            a.fields["transport"] = f.get("transport")
            a.fields["connect_ms"] = as_int(f.get("connect_ms"))
            finish(a, "connected")
            a.awaiting_caps = True
            continue
        if mid == "conn.caps":
            a = next((x for x in attempts if x.awaiting_caps), None)
            if a is not None:
                a.add(r)
                a.awaiting_caps = False
                a.fields.update(_caps_fields(r))
            else:
                events.append(_event(info, "capabilities", [r], "capabilities record without a connected record",
                                     _caps_fields(r), r.sensitive))
            continue
        if mid in ("http.fail", "sse.fail", "proxy.fail", "conn.timeout"):
            a = oldest_open()
            if a is not None:
                a.add(r)
                a.fields.setdefault("failure_details", []).append(_short(r.display, 200))
                continue
        if mid == "conn.fail":
            a = oldest_open()
            if a is None:
                a = _Attempt(r)
                attempts.append(a)
            else:
                a.add(r)
            a.fields["elapsed_ms"] = as_int(f.get("elapsed_ms"))
            if f.get("code"):
                a.fields["failure_code"] = f.get("code")
            a.fields["failure_message"] = r.display[r.display.find(": ") + 2:] if ": " in r.display else r.display
            finish(a, "failed")
            failed_recent.append(a)
            continue
        if mid in ("conn.fail_error", "conn.error_stack", "conn.error_object"):
            target = oldest_open() if mid in ("conn.error_stack", "conn.error_object") else None
            if target is None and failed_recent:
                target = failed_recent[-1]
            if target is None:
                target = oldest_open()
            if target is not None:
                target.add(r)
                if mid in ("conn.error_stack", "conn.error_object"):
                    target.fields["error_object"] = f.get("error_name")
                continue
        if mid == "oauth.no_token":
            a = oldest_open()
            if a is not None:
                a.add(r)
            continue
        if mid in ("chan.skipped",):
            continue  # process marker, counted per file

        # ---- everything else: one event per record ----
        cat = r.category
        ev = _EVENT_BY_CATEGORY.get(cat, cat)
        summary = _short(r.display, 200)
        flds = output_fields(r.cls, r.withheld)
        in_call = [c for c in in_flight]
        if len(in_call) == 1 and cat in ("elicitation", "roots"):
            flds["during_call"] = in_call[0].model.tool
            flds["during_call_source"] = in_call[0].model.source
        if mid in ("elicit.response", "elicit.hook"):
            m = re.search(r'"action"\s*:\s*"([^"]*)"', r.message)
            if m:
                flds["action"] = m.group(1)
                summary = f"elicitation response: {m.group(1)}"
        elif mid in ("elicit.request", "elicit.request_print", "elicit.request_init"):
            m = re.search(r'"mode"\s*:\s*"([^"]*)"', r.message)
            flds["mode"] = m.group(1) if m else None
            summary = ("elicitation request" + (f" ({m.group(1)})" if m else "")
                       + (" in print mode (no response record expected)" if mid == "elicit.request_print" else ""))
        if cat == UNCLASSIFIED:
            summary = f"unclassified {r.key} record: {_short(r.display, 160)}"
        events.append(_event(info, ev, [r], summary, flds, r.sensitive))

    flush_shutdown()

    for bc in retried:
        lc = bc.model
        fe = bc.first_end
        fsec = fe.fields().get("seconds", "?") if fe is not None else "?"
        d1 = f" (+{fe.ts - bc.start.ts} ms)" if fe is not None and fe.ts is not None and bc.start.ts is not None else ""
        d2 = ""
        if bc.end is not None and bc.end.ts is not None and bc.retry_start.ts is not None:
            d2 = f" (+{bc.end.ts - bc.retry_start.ts} ms)"
        err = ""
        if fe is not None:
            span = fe.cls.span("message")
            raw = fe.message[span[0]:span[1]] if span else None
            shown, _items = withhold_text("tool-error-text", raw, fe.source, policy)  # item already in lc.sensitive
            if shown:
                err = f": {_short(shown, 120)}"
        for be in events:
            if be.anchor is bc.retrying:
                be.model.fields["retry_of_call"] = bc.start.source
                be.model.fields["retry_calling"] = bc.retry_start.source
        lc.notes.insert(0, f"retried after session recovery; first attempt failed after {fsec}s")
        # every record of a stream is in one file (the call's source)
        lc.notes.insert(1, f"attempt 1: Calling (line {bc.start.line}), failed after {fsec}s (line "
                           f"{fe.line if fe is not None else '?'}){d1}{err}; 'Retrying tool' record (line "
                           f"{bc.retrying.line}); attempt 2: Calling (line {bc.retry_start.line}), "
                           f"{_attempt_text(lc.outcome, lc.duration, bc.end)}{d2}")

    for a in attempts:
        flds = dict(a.fields)
        flds["outcome"] = a.outcome
        flds.setdefault("transport", a.transport_hint)
        # remote URL from the transport record, as displayed (withheld parts stay withheld)
        to = f" to {flds['url']}" if flds.get("url") else ""
        if a.outcome == "connected":
            summary = f"connected ({flds.get('transport')}){to} in {flds.get('connect_ms')} ms"
            if flds.get("server_version"):
                summary += f"; serverVersion {flds['server_version']}"
        elif a.outcome == "failed":
            code = f" ({flds['failure_code']})" if flds.get("failure_code") else ""
            summary = (f"connection{to} failed after {flds.get('elapsed_ms')} ms{code}: "
                       f"{_short(flds.get('failure_message'), 140)}")
        else:
            summary = f"connection attempt{to} without outcome record"
        if flds.get("stderr_records"):
            summary += f"; stderr at connect ({flds['stderr_records']} record(s))"
        if flds.get("overlaps_other_attempt"):
            summary += "; overlaps another attempt in the same file"
        sess = next((r.session_id for r in reversed(a.recs) if r.session_id), None)
        first_sid = a.recs[0].session_id
        if first_sid and sess and first_sid != sess:
            flds["first_record_session"] = first_sid
        events.append(_event(info, "connect", a.recs, summary, flds, a.sensitive, session=sess))

    return calls, events
