"""Joins between the MCP log, the --debug file and the transcripts.

1. cross_check(): every --debug mirror line against the MCP-log records in
   scope (same sanitized server name, same kind, same session id when the
   debug file name carries one, MCP-log timestamp 5 ms before to 50 ms after
   the debug line). Text is "identical" after trimming, "redaction-only" when
   it matches once each [REDACTED] in the debug copy may stand for any text,
   or "error-object" when the debug text is the first line of the logged
   stack. Leftovers of the same template are paired as "differs from debug
   copy"; the rest is reported as present in only one source.

2. join_calls(): MCP-log (or debug-only) tool calls against transcript
   tool_use blocks. A toolUseId from '[Stall] tool_dispatch_start' pins the
   call when a debug file exists. Otherwise: same sessionId, same sanitized
   server and tool, the tool_use not later than the log call (+50 ms) and
   within a window (60 s for files with headless markers, 24 h otherwise),
   and a tool_result that is not earlier than the log completion (-50 ms)
   nor more than 10 s after it. Among the remaining candidates the one whose
   result follows the completion most closely wins, then the earliest
   tool_use; a tie is reported as ambiguous and nothing is forced.

Nothing here interprets an offset or a mismatch; both are reported as found.
"""
from __future__ import annotations

import bisect
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Optional

from .mcplog import BuiltCall, Rec, enc, hc, ts_ms
from .models import CrossCheck, CrossCheckItem, SensitiveItem, ToolCall, ToolCallLogInfo
from .sensitive import SensitivePolicy, decode_json_fragment, make_item, spans_for_message

REDACTED = "[REDACTED]"
WINDOW_BEFORE_MS = -5  # MCP-log ts - debug ts, lower bound
WINDOW_AFTER_MS = 50
SPAN_SLACK_MS = 2000


# ---------------------------------------------------------------------------
# 1. debug file <-> MCP log
# ---------------------------------------------------------------------------


@dataclass
class DebugScope:
    path: str
    session_id: Optional[str]
    first_ms: Optional[int]
    last_ms: Optional[int]


def _compare(debug_text: str, log_rec: Rec) -> tuple[str, list[tuple[int, int]]]:
    """Return (status, masked spans in the ORIGINAL log message)."""
    msg = log_rec.message
    lead = len(msg) - len(msg.lstrip())
    lt = msg.strip()
    if debug_text == lt:
        return "identical", []
    if REDACTED in debug_text:
        parts = debug_text.split(REDACTED)
        if len(parts) <= 40:
            rx = re.compile("(.+?)".join(re.escape(p) for p in parts), re.S)
            m = rx.fullmatch(lt)
            if m:
                # groups that are "[REDACTED]" in the MCP log too were masked before both writes
                spans = [(m.start(i) + lead, m.end(i) + lead) for i in range(1, len(parts)) if m.group(i) != REDACTED]
                return "redaction-only", spans
    if log_rec.key == "error" and lt.startswith(debug_text) and re.match(r"\n\s+at ", lt[len(debug_text):]):
        return "error-object", []
    return "differs", []


def _masked_items(log_rec: Rec, spans: list[tuple[int, int]], policy: SensitivePolicy) -> list[SensitiveItem]:
    """The MCP-log values the debug redactor masked. A masked span that
    overlaps a value MCPeek withholds is trimmed to that value (the redactor
    can swallow a closing quote), so size and hash prefix equal the withheld
    item's."""
    sens = spans_for_message(log_rec.cls.mask, log_rec.message, log_rec.cls if log_rec.cls.entry else None,
                             log_rec.message_id, log_rec.key)
    items = []
    for s, e in spans:
        kind, fld, json_escaped = "masked-by-debug-redactor", None, False
        for sp in sens:
            if s < sp.end and sp.start < e:
                kind, fld = sp.kind, sp.field
                s, e = max(s, sp.start), min(e, sp.end)
                json_escaped = sp.json_escaped and (s, e) == (sp.start, sp.end)
                break
        raw = log_rec.message[s:e]
        items.append(make_item(kind, decode_json_fragment(raw) if json_escaped else raw, log_rec.source, policy, fld))
    return items


def cross_check(log_recs: list[Rec], debug_recs: list[Rec], scopes: list[DebugScope],
                policy: SensitivePolicy, context: list[str]) -> CrossCheck:
    cc = CrossCheck(debug_files=len(scopes), debug_mirror_lines=len(debug_recs), context=list(context))
    if not scopes:
        return cc

    def in_scope(r: Rec) -> bool:
        if r.key == "invalid" or r.ts is None:
            return False
        for s in scopes:
            if s.first_ms is None or s.last_ms is None:
                continue
            if not (s.first_ms - SPAN_SLACK_MS <= r.ts <= s.last_ms + SPAN_SLACK_MS):
                continue
            if s.session_id is None or r.session_id == s.session_id:
                return True
        return False

    scoped = [r for r in log_recs if in_scope(r)]
    cc.mcp_log_records_in_scope = len(scoped)
    by_key: dict[tuple[str, str], list[Rec]] = defaultdict(list)
    for r in scoped:
        by_key[(r.server_dir, r.key)].append(r)
    for lst in by_key.values():
        lst.sort(key=lambda r: (r.ts, r.source_path, r.line))
    ts_index = {k: [r.ts for r in v] for k, v in by_key.items()}
    used: set[int] = set()
    offsets: Counter = Counter()

    def window(d: Rec) -> list[Rec]:
        k = (d.server_dir, d.key)
        lst = by_key.get(k, [])
        if d.ts is None or not lst:
            return []
        lo = bisect.bisect_left(ts_index[k], d.ts + WINDOW_BEFORE_MS)
        hi = bisect.bisect_right(ts_index[k], d.ts + WINDOW_AFTER_MS)
        return [r for r in lst[lo:hi] if id(r) not in used]

    pending_debug: list[Rec] = []
    for d in debug_recs:
        cands = window(d)
        same_sess = [r for r in cands if d.session_id is None or r.session_id == d.session_id]
        pool = same_sess or cands
        best = None
        for r in pool:
            status, spans = _compare(d.message, r)
            if status == "differs":
                continue
            key = (abs(r.ts - d.ts), r.line)
            if best is None or key < best[0]:
                best = (key, r, status, spans)
        if best is None:
            pending_debug.append(d)
            continue
        _, r, status, spans = best
        used.add(id(r))
        _link(cc, d, r, status, offsets, policy, spans)

    # second pass: same template, text differs beyond redaction
    leftover_debug: list[Rec] = []
    for d in pending_debug:
        cands = [r for r in window(d) if r.message_id == d.message_id]
        same_sess = [r for r in cands if d.session_id is None or r.session_id == d.session_id]
        pool = same_sess or cands
        if not pool:
            leftover_debug.append(d)
            continue
        r = min(pool, key=lambda r: (abs(r.ts - d.ts), r.line))
        used.add(id(r))
        _link(cc, d, r, "differs from debug copy", offsets, policy, [])

    for d in leftover_debug:
        cc.debug_only += 1
        d.xref_status = "debug only"
        cc.items.append(CrossCheckItem(
            status="debug only", server=d.raw_server or d.server_dir, message_id=d.message_id,
            debug_source=d.source, debug_timestamp=d.timestamp, debug_text=d.display,
        ))
    for r in scoped:
        if id(r) in used:
            continue
        cc.mcp_log_only += 1
        r.xref_status = "mcp-log only"
        cc.items.append(CrossCheckItem(
            status="mcp-log only", server=r.server_dir, message_id=r.message_id,
            mcp_log_source=r.source, mcp_log_timestamp=r.timestamp, text=r.display,
        ))

    # order: within each debug stream, matched MCP-log lines of one file must increase
    last: dict[tuple[str, str], int] = {}
    for d in debug_recs:
        if d.xref is None:
            continue
        k = (d.stream, d.xref.source_path)
        if k in last and d.xref.line < last[k]:
            cc.order_inversions += 1
        last[k] = max(last.get(k, 0), d.xref.line)

    cc.offset_histogram_ms = {str(k): v for k, v in sorted(offsets.items())}
    cc.offsets_outside_0_5ms = sum(v for k, v in offsets.items() if not 0 <= k <= 5)
    return cc


def _link(cc: CrossCheck, d: Rec, r: Rec, status: str, offsets: Counter, policy: SensitivePolicy,
          spans: list[tuple[int, int]]) -> None:
    d.xref, r.xref = r, d
    d.xref_status = r.xref_status = status
    off = (r.ts - d.ts) if (r.ts is not None and d.ts is not None) else None
    if off is not None:
        offsets[off] += 1
    cc.matched += 1
    if status == "identical":
        cc.identical += 1
    elif status == "redaction-only":
        cc.redaction_only += 1
    elif status == "error-object":
        cc.error_object += 1
    else:
        cc.differs += 1
    if d.session_id and r.session_id and d.session_id != r.session_id:
        cc.session_mismatches += 1
    if status != "identical":
        notes = []
        if status == "redaction-only":
            notes.append(f"{len(spans)} value(s) masked in the debug copy and kept in the MCP log")
        if status == "error-object":
            notes.append("the MCP log has the error stack, the debug copy its first line")
        cc.items.append(CrossCheckItem(
            status=status, server=d.raw_server or r.server_dir, message_id=r.message_id,
            mcp_log_source=r.source, debug_source=d.source, mcp_log_timestamp=r.timestamp,
            debug_timestamp=d.timestamp, offset_ms=off, masked_in_debug=_masked_items(r, spans, policy),
            text=r.display, debug_text=d.display, notes=notes,
        ))


# ---------------------------------------------------------------------------
# 2. log calls <-> transcript tool_use
# ---------------------------------------------------------------------------

INF = float("inf")
HEADLESS_WINDOW_MS = 60_000
DEFAULT_WINDOW_MS = 86_400_000
PRE_TOLERANCE_MS = 50
RESULT_BEFORE_MS = 50
RESULT_AFTER_MS = 10_000


@dataclass
class _TU:
    call: ToolCall
    use_ms: Optional[int]
    res_ms: Optional[int]
    order: int
    assigned: bool = False
    candidate_of: list = None  # type: ignore[assignment]


def _server_of_match(lc, transcript_server: str) -> str:
    """Server name of a log call joined to a transcript call: the candidate
    name the transcript name stands for, else the transcript name."""
    names = [c for c in lc.server_candidates if hc(c) == transcript_server]
    return names[0] if len(names) == 1 else transcript_server


def join_calls(calls: list[BuiltCall], tool_calls: list[ToolCall], transcript_sessions: set[str],
               log_sessions_by_server: dict[str, set[str]]) -> None:
    tus: list[_TU] = []
    by_key: dict[tuple[str, str, str], list[_TU]] = defaultdict(list)
    by_id: dict[tuple[str, str], list[_TU]] = defaultdict(list)
    for i, c in enumerate(tool_calls):
        if not c.is_mcp or not c.mcp_server or not c.mcp_tool:
            continue
        tu = _TU(c, ts_ms(c.timestamp), ts_ms(c.result_timestamp), i, candidate_of=[])
        tus.append(tu)
        by_key[(c.session_uuid, enc(c.mcp_server), enc(c.mcp_tool))].append(tu)
        by_id[(c.session_uuid, c.tool_use_id)].append(tu)

    def assign(bc: BuiltCall, tu: _TU, method: str) -> None:
        lc = bc.model
        tu.assigned = True
        lc.join_status = "matched"
        lc.join_method = method
        lc.tool_use_id = tu.call.tool_use_id
        lc.transcript_path = tu.call.source_path
        lc.agent_id = tu.call.agent_id
        if bc.start_ms is not None and tu.use_ms is not None:
            lc.call_offset_ms = bc.start_ms - tu.use_ms
        if bc.end_ms is not None and tu.res_ms is not None:
            lc.result_offset_ms = tu.res_ms - bc.end_ms
        name = _server_of_match(lc, tu.call.mcp_server or "")
        if name and name != lc.server:
            lc.notes.append(f"server name from the matched transcript call: {tu.call.mcp_server}")
            lc.server = name
        tu.call.log = _log_info(bc, "matched", method)

    # pass 1: toolUseId from the debug file
    for bc in calls:
        d = bc.model.dispatch
        if d is None:
            continue
        same_id = by_id.get((bc.model.session_id or "", d.tool_use_id), [])
        if not same_id:
            bc.model.notes.append(f"toolUseId {d.tool_use_id} (debug file) not found in the transcripts of this session")
            continue
        free = [t for t in same_id if not t.assigned]
        if not free:
            bc.model.notes.append(f"toolUseId {d.tool_use_id} (debug file) already joined to another log call")
            continue
        if len(free) > 1:
            # the id is recorded more than once: only a tool_use inside the
            # time window of the log call fits (see pass 2)
            window = HEADLESS_WINDOW_MS if bc.model.process_mode == "headless-or-mcp-list" else DEFAULT_WINDOW_MS
            free = [t for t in free if bc.start_ms is not None and t.use_ms is not None
                    and t.use_ms <= bc.start_ms + PRE_TOLERANCE_MS and bc.start_ms - t.use_ms <= window]
            if len(free) != 1:
                lc = bc.model
                lc.notes.append(f"toolUseId {d.tool_use_id} (debug file) is recorded {len(same_id)} times in the "
                                f"transcripts of this session; {len(free)} of them fit the time window")
                if free:
                    lc.join_status = "ambiguous"
                    lc.candidate_tool_use_ids = [t.call.tool_use_id for t in free]
                    for t in free:
                        t.candidate_of.append(bc)
                continue
        assign(bc, free[0], "toolUseId from debug file")

    # pass 2: session + server + tool + time
    groups: dict[tuple[str, str, str], list[BuiltCall]] = defaultdict(list)
    for bc in calls:
        if bc.model.join_status in ("matched", "ambiguous"):
            continue
        groups[(bc.model.session_id or "", bc.model.server_dir, enc(bc.model.tool))].append(bc)
    for key, bcs in groups.items():
        bcs.sort(key=lambda b: (b.start_ms if b.start_ms is not None else 0, b.model.source))
        cand_all = by_key.get(key, [])
        for bc in bcs:
            lc = bc.model
            if bc.start_ms is None:
                lc.notes.append("Calling record without a usable timestamp")
                continue
            window = HEADLESS_WINDOW_MS if lc.process_mode == "headless-or-mcp-list" else DEFAULT_WINDOW_MS
            cands = [t for t in cand_all if not t.assigned and t.use_ms is not None
                     and t.use_ms <= bc.start_ms + PRE_TOLERANCE_MS and bc.start_ms - t.use_ms <= window]
            ok = []
            for t in cands:
                if t.res_ms is not None:
                    if bc.end_ms is not None:
                        gap = t.res_ms - bc.end_ms
                        if gap < -RESULT_BEFORE_MS or gap > RESULT_AFTER_MS:
                            continue
                    elif t.res_ms < bc.start_ms - RESULT_BEFORE_MS:
                        continue
                ok.append(t)
            if not ok:
                if cands:
                    lc.notes.append(f"{len(cands)} transcript call(s) of this tool rejected by result timing")
                continue

            def rank(t: _TU):
                gap = (t.res_ms - bc.end_ms) if (bc.end_ms is not None and t.res_ms is not None) else INF
                return (abs(gap) if gap != INF else INF, t.use_ms)

            ok.sort(key=lambda t: (rank(t), t.order))
            if len(ok) > 1 and rank(ok[0]) == rank(ok[1]):
                lc.join_status = "ambiguous"
                lc.candidate_tool_use_ids = [t.call.tool_use_id for t in ok if rank(t) == rank(ok[0])]
                for t in ok:
                    if rank(t) == rank(ok[0]):
                        t.candidate_of.append(bc)
                continue
            assign(bc, ok[0], "session, server, tool and time")

    # unmatched log calls: neutral context
    for bc in calls:
        lc = bc.model
        if lc.join_status == "unmatched":
            if (lc.session_id or "") not in transcript_sessions:
                lc.notes.append("no transcript file for this sessionId")
            else:
                lc.notes.append("no transcript tool_use of this server and tool fits")

    # transcript side
    for tu in tus:
        c = tu.call
        if c.log is not None:
            continue
        if tu.candidate_of:
            c.log = ToolCallLogInfo(status="ambiguous", candidate_sources=[b.model.source for b in tu.candidate_of],
                                    notes=["more than one transcript call fits the same log call"])
            continue
        has_log = c.session_uuid in log_sessions_by_server.get(enc(c.mcp_server or ""), set())
        c.log = ToolCallLogInfo(status="no log record", log_file_for_session=has_log)


def _log_info(bc: BuiltCall, status: str, method: str) -> ToolCallLogInfo:
    lc = bc.model
    return ToolCallLogInfo(
        status=status, method=method, source=lc.source, source_kind=lc.source_kind, outcome=lc.outcome,
        duration=lc.duration, end_timestamp=lc.end_timestamp, timestamp_delta_ms=lc.timestamp_delta_ms,
        call_offset_ms=lc.call_offset_ms,
        result_offset_ms=lc.result_offset_ms, heartbeats_s=list(lc.heartbeats_s), dispatch=lc.dispatch,
        notes=list(lc.notes),
    )
