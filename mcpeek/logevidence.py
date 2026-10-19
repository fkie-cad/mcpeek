"""Assembles MCP-log and --debug evidence into the case.

Order: parse debug files (entries that repeat an earlier debug file are
counted once) -> parse MCP logs -> cross-check debug mirror lines against
MCP-log records -> analyse MCP-log streams and debug mirror streams (debug
items whose anchor record has an MCP-log twin are dropped, the rest is kept
as debug-only evidence) -> pin calls by toolUseId -> join calls to
transcripts -> per-server summaries. Under a session filter the analysis
runs on the files loader.plan_log_files() chose (closed under the debug
pairing window), the summaries cover the files shown, and the output keeps
the calls, events, records and cross-check of the selected sessions (the
rest is counted per file).
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import safejson
from .correlate import DebugScope, cross_check, join_calls
from .debuglog import ParsedDebugFile, file_retry_links, pair_dispatch, parse_debug_file
from .loader import DiscoveredTarget
from .mcplog import (
    BuiltCall,
    BuiltEvent,
    Rec,
    StreamInfo,
    analyze_stream,
    enc,
    hc,
    mask_rec,
    output_fields,
    read_mcp_log,
    retry_dispatch_note,
    ts_ms,
)
from .models import (
    CacheRoot,
    CrossCheck,
    DebugFile,
    DebugServerInfo,
    FilteredFile,
    LatestLink,
    LogCall,
    LogServerSummary,
    McpLogFile,
    Server,
    ServerEvent,
    Session,
    ToolCall,
)
from .sensitive import SensitivePolicy, apply_spans, spans_for_message


# ---------------------------------------------------------------------------
# Server-name candidates (the MCP-log folder name is sanitized and lossy)
# ---------------------------------------------------------------------------


class NameIndex:
    def __init__(self) -> None:
        self._names: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))

    def add(self, name: Optional[str], source: str) -> None:
        if name:
            self._names[enc(name)][name].add(source)

    def candidates(self, folder: str) -> list[str]:
        names = self._names.get(folder, {})
        exact = [n for n, srcs in names.items() if srcs != {"transcript"}]
        exact_hc = {hc(n) for n in exact}
        out = sorted(exact)
        for n, srcs in sorted(names.items()):
            if srcs == {"transcript"} and n not in exact_hc:
                out.append(n)
        return out

    def resolve(self, folder: str) -> tuple[str, list[str], str]:
        """(display name, candidate names, unique | ambiguous | unknown). A
        folder shared by several names is shown as "<folder> (shared by: a, b)"."""
        c = self.candidates(folder)
        if len(c) == 1:
            return c[0], c, "unique"
        if len(c) > 1:
            return shared_label(folder, c), c, "ambiguous"
        return folder, c, "unknown"


def shared_label(folder: str, names: list[str]) -> str:
    return f"{folder} (shared by: {', '.join(names)})"


def possibly_shared_label(folder: str) -> str:
    return f"{folder} (possibly shared by servers whose names sanitize to {folder})"


def _config_names(path: Optional[Path], warnings: list[str]) -> list[str]:
    if path is None:
        return []
    data = safejson.read_object(path, warnings)
    if data is None:
        return []
    names = list(safejson.object_field(data.get("mcpServers"), f"{path}: mcpServers", warnings) or {})
    projects = data.get("projects")
    if isinstance(projects, dict):
        for key, p in projects.items():
            if isinstance(p, dict):
                names += list(safejson.object_field(p.get("mcpServers"), f"{path}: projects.{key}.mcpServers",
                                                    warnings) or {})
    return names


def _ts_key(ts: str) -> tuple:
    ms = ts_ms(ts)
    return (0, ms, ts) if ms is not None else (1, 0, ts)


# records whose url group is the connect event's "url" field (see analyze_stream)
_URL_RECORDS = ("http.init", "ws.init", "sse.ide", "proxy.using")


def _recorded_url(be: BuiltEvent) -> Optional[str]:
    """The recorded URL behind a connect event's "url" field, for comparison
    with a configured URL only (never output: query values can be secrets)."""
    for r in be.recs:
        if r.message_id in _URL_RECORDS and r.fields().get("url"):
            return r.fields()["url"]
    return None


def _event_order(e: ServerEvent) -> tuple:
    """Time order (offsets normalized), then source file and line."""
    ms = ts_ms(e.timestamp)
    path, _, line = e.source.rpartition(":")
    rank = 0 if ms is not None else (1 if e.timestamp else 2)
    return (rank, ms or 0, e.timestamp or "", path, int(line) if line.isdigit() else 0, e.event)


def _shared_folder_signs(info: McpLogFile, calls: list[BuiltCall], events: list[BuiltEvent]) -> None:
    """Signs that several servers write to one MCP-log file: overlapping
    connection attempts, or a shutdown group that repeats a step. With at
    most one known name for the folder the file is flagged as possibly
    shared, and its unattributed calls and events are labelled so."""
    signs = []
    if info.overlapping_connects:
        signs.append("overlapping connection attempts")
    repeated = sorted({s for e in events for s in e.model.fields.get("repeated_steps", [])})
    if repeated:
        signs.append("repeated shutdown steps (" + ", ".join(repeated) + ")")
    info.shared_folder_signs = signs
    if not signs:
        return
    if len(info.name_candidates) > 1:
        info.notes.append("signs of several servers in this file: " + "; ".join(signs) + " (folder shared by: "
                          + ", ".join(info.name_candidates) + ")")
        return
    info.possibly_shared = True
    known = f"known name: {info.name_candidates[0]}" if info.name_candidates else "no name known"
    info.notes.append(f"possibly shared by servers whose names sanitize to {info.server_dir}: " + "; ".join(signs)
                      + f" ({known})")
    label = possibly_shared_label(info.server_dir)
    for be in events:
        if "server_from" not in be.model.fields:
            be.model.server = label
            be.model.fields["folder_possibly_shared"] = True
    for bc in calls:
        bc.model.server = label  # a call joined to a transcript call gets that call's server name


def drop_repeated_debug_entries(parsed: list[ParsedDebugFile]) -> None:
    """A debug file can repeat entries of an earlier one, for example a
    regular-file copy of ``latest`` that is a few lines longer or shorter
    than the session file it was copied from. Each entry that equals an entry
    of an earlier debug file (same level, server, text and timestamp; the
    toolUseId is part of the text of dispatch lines) is noted on the entry and
    counted once, from the earlier file."""
    earlier: dict[tuple, dict[str, list[int]]] = {}
    for p in parsed:
        counts: Counter = Counter()
        mine: dict[tuple, list[int]] = defaultdict(list)
        dup: dict[int, str] = {}  # line -> file:line of the earlier entry

        def check(key: tuple, line: int) -> None:
            counts[key] += 1
            mine[key].append(line)
            for path, lines in earlier.get(key, {}).items():
                if len(lines) >= counts[key]:
                    dup[line] = f"{path}:{lines[counts[key] - 1]}"
                    return

        for r in p.mirror_recs:
            check(("mirror", r.level, r.raw_server, r.key, r.message, r.timestamp), r.line)
        for e, _c in p.catalog_entries:
            check(("line", e.level, e.message, e.timestamp), e.line)
        for key, lines in mine.items():
            earlier.setdefault(key, {})[p.info.path] = lines
        if not dup:
            continue

        def line_of(source: str) -> int:
            tail = source.rpartition(":")[2]
            return int(tail) if tail.isdigit() else -1

        p.mirror_recs = [r for r in p.mirror_recs if r.line not in dup]
        p.catalog_entries = [(e, c) for e, c in p.catalog_entries if e.line not in dup]
        p.dispatch_starts = [d for d in p.dispatch_starts if line_of(d.source) not in dup]
        p.dispatch_ends = {k: v for k, v in p.dispatch_ends.items() if line_of(v[2]) not in dup}
        p.server_infos = [i for i in p.server_infos if i.debug_log_line not in dup]
        for x in p.info.mcp_entries:
            if x.line in dup:
                x.notes.append(f"same entry as {dup[x.line]} (counted once, from there)")
        p.info.duplicate_entries = len(dup)
        p.info.duplicates_of = sorted({v.rpartition(":")[0] for v in dup.values()})
        p.info.notes.append(f"{len(dup)} entr(y/ies) repeat entries of {', '.join(p.info.duplicates_of)} (same "
                            "server, text and timestamp): counted once, from that file")


# ---------------------------------------------------------------------------


@dataclass
class LogEvidence:
    cache_roots: list[CacheRoot] = field(default_factory=list)
    mcp_log_files: list[McpLogFile] = field(default_factory=list)
    debug_files: list[DebugFile] = field(default_factory=list)
    latest_links: list[LatestLink] = field(default_factory=list)
    log_calls: list[LogCall] = field(default_factory=list)
    events: list[ServerEvent] = field(default_factory=list)
    summaries: list[LogServerSummary] = field(default_factory=list)
    cross_check: Optional[CrossCheck] = None
    debug_server_infos: list[DebugServerInfo] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    filtered_out: list[FilteredFile] = field(default_factory=list)  # session filter: left out, per file


def build_log_evidence(discovered: DiscoveredTarget, servers: list[Server], sessions: list[Session],
                       tool_calls: list[ToolCall], policy: SensitivePolicy) -> LogEvidence:
    ev = LogEvidence()

    # --- name candidates -----------------------------------------------------
    names = NameIndex()
    for s in servers:
        names.add(s.name, "config")
    for b in discovered.backup_paths:
        for n in _config_names(b, ev.warnings):
            names.add(n, "config-backup")
    for c in tool_calls:
        if c.is_mcp:
            names.add(c.mcp_server, "transcript")

    # --- debug files -------------------------------------------------------------
    parsed_debug: list[ParsedDebugFile] = []
    for dp in discovered.debug_files:
        try:
            pdf = parse_debug_file(dp, policy)
        except Exception as exc:  # defensive: one bad file must not stop the run
            ev.warnings.append(f"failed to parse debug file {dp.path}: {exc}")
            continue
        parsed_debug.append(pdf)
    drop_repeated_debug_entries(parsed_debug)
    for pdf in parsed_debug:
        for s in pdf.info.servers:
            names.add(s, "debug-file")
    for lf in discovered.debug_latest:
        ev.latest_links.append(LatestLink(path=str(lf.path), kind=lf.kind, target=lf.target,
                                          resolves_to=lf.resolves_to, identical_to=lf.identical_to))

    # --- MCP logs ------------------------------------------------------------------
    roots_count: dict[str, int] = defaultdict(int)
    log_streams: list[tuple[McpLogFile, list[Rec]]] = []
    for mp in discovered.mcp_log_paths:
        server, cands, status = names.resolve(mp.server_dir)
        try:
            info, recs = read_mcp_log(mp.path, cache_root=str(mp.cache_root), encoded_cwd=mp.encoded_cwd,
                                      server_dir=mp.server_dir, server=server, name_candidates=cands,
                                      name_status=status, policy=policy)
        except Exception as exc:  # defensive
            ev.warnings.append(f"failed to parse MCP log {mp.path}: {exc}")
            continue
        roots_count[str(mp.cache_root)] += 1
        log_streams.append((info, recs))
        ev.mcp_log_files.append(info)
    for cr in discovered.cache_roots:
        ev.cache_roots.append(CacheRoot(path=str(cr.path), origin=cr.origin, status=cr.status,
                                        log_files=roots_count.get(str(cr.path), 0)))

    # --- cross-check --------------------------------------------------------------
    flt = discovered.filter
    ids: set[str] = set(flt.session_ids) if flt is not None else set()
    eff = _effective_sessions(log_streams) if flt is not None else {}
    if flt is not None and policy.show:
        # session filter: the values of other sessions' records stay withheld,
        # also with --show-sensitive (in the text of the rows kept from them)
        withhold = SensitivePolicy(show=False)
        for _, recs in log_streams:
            for r in recs:
                if eff.get(id(r)) not in ids and eff.get(id(r)) is not None:
                    mask_rec(r, withhold)
    all_log_recs = [r for _, recs in log_streams for r in recs]
    debug_recs = [r for p in parsed_debug for r in p.mirror_recs]
    # scope of each debug file: its session id (from the name) and its own time span
    scopes = [DebugScope(p.info.path, p.info.session_id, ts_ms(p.info.first_timestamp), ts_ms(p.info.last_timestamp))
              for p in parsed_debug]
    if flt is not None:
        # session filter: the debug files not analysed keep their scope (loader.plan_log_files)
        scopes += [DebugScope(path, sid, first, last) for path, sid, first, last in flt.extra_scopes]
    context = []
    for p in parsed_debug:
        for path in p.info.log_batches_dropped:
            context.append(f"{p.info.path}: 'Dropping log batch for {path}' (MCP-log write failed)")
    if parsed_debug or (flt is not None and flt.extra_scopes):
        ev.cross_check = cross_check(all_log_recs, debug_recs, scopes, policy, context)
    pair_session = {id(d): d.session_id for d in debug_recs}  # the debug-side session id the pairing used
    # session id of debug files without one in the name, from matched records
    for p in parsed_debug:
        if p.info.session_id is None:
            sids = sorted({r.xref.session_id for r in p.mirror_recs if r.xref is not None and r.xref.session_id})
            if len(sids) == 1:
                p.info.session_id = sids[0]
                p.info.session_id_source = "matched MCP log records"
                for r in p.mirror_recs:
                    r.session_id = r.session_id or sids[0]
            elif len(sids) > 1:
                p.info.session_id_source = "matched MCP log records (several: " + ", ".join(sids) + ")"

    # --- session filter: the files shown ----------------------------------------------------
    # The MCP-log files in which a selected session appears, and the debug
    # files named after a selected session or paired with its records; the
    # other analysed files only complete the pairing (loader.plan_log_files).
    shown: Optional[set[str]] = None
    if flt is not None:
        shown = set(flt.shown_mcp_logs)
        for p in parsed_debug:
            if p.info.session_id in ids or any(r.xref is not None and eff.get(id(r.xref)) in ids for r in p.mirror_recs):
                shown.add(p.info.path)

    # --- transcripts: sessions, cwd hints --------------------------------------------------
    # Under a session filter only the selected transcripts are parsed; the
    # session ids and first cwd of the others come from their first records,
    # so that notes and joins of the selected sessions stay as unfiltered.
    transcript_sessions = {s.session_uuid for s in sessions}
    cwd_by_session = {s.session_uuid: sorted(s.cwds)[0] for s in sessions if s.cwds}
    if flt is not None:
        transcript_sessions |= flt.known_session_ids
        for sid, cwd in flt.cwd_by_session.items():
            cwd_by_session.setdefault(sid, cwd)
    for p in parsed_debug:
        if p.info.session_id:
            p.info.has_transcript = p.info.session_id in transcript_sessions
            if not p.info.has_transcript:
                p.info.notes.append("no transcript for this session id"
                                    + (f"; continues session {p.info.resumes_session}" if p.info.resumes_session else ""))

    # --- stream analysis -------------------------------------------------------------
    built_calls: list[BuiltCall] = []
    built_events: list[BuiltEvent] = []
    stream_meta: dict[int, tuple[str, Optional[str], str]] = {}  # id(BuiltX) -> (server_dir, encoded_cwd, file)
    error_counts: dict[tuple[Optional[str], str], int] = defaultdict(int)
    stderr_counts: dict[tuple[Optional[str], str], int] = defaultdict(int)
    for info, recs in log_streams:
        si = StreamInfo(info.server, info.server_dir, info.name_candidates, "mcp-log", info.mode,
                        cwd_hint=info.cwds[0] if info.cwds else None)
        try:
            calls, events = analyze_stream(recs, si, policy)
        except Exception as exc:  # defensive: one bad file must not stop the run
            ev.warnings.append(f"failed to analyse MCP log {info.path}: {exc}")
            calls, events = [], []
        info.connect_attempts = sum(1 for e in events if e.model.event == "connect")
        orphan = info.leading_single_record_session
        if orphan:
            for e in events:
                if e.model.event == "connect" and e.model.fields.get("first_record_session") == orphan:
                    has_tr = orphan in transcript_sessions
                    e.model.fields["first_record_session_single_line"] = True
                    e.model.fields["first_record_session_has_transcript"] = has_tr
                    e.model.summary += (f"; first record carries session id {orphan} (on no other line of this file"
                                        + ("" if has_tr else ", no transcript") + "; the pattern written by --continue)")
        info.overlapping_connects = any(e.model.fields.get("overlaps_other_attempt") for e in events)
        _shared_folder_signs(info, calls, events)
        for sw in info.session_switches:
            anchor = next((r for r in recs if r.line == sw.line), None)
            if anchor is None:
                continue
            events.append(BuiltEvent(ServerEvent(
                event="session-switch", timestamp=sw.timestamp, session_uuid=sw.to_session, cwd=anchor.cwd,
                server=info.server, server_dir=info.server_dir, server_candidates=info.name_candidates,
                summary=f"sessionId changes from {sw.from_session} to {sw.to_session} within one MCP-log file "
                        "(same process; /clear writes this pattern)",
                fields={"from_session": sw.from_session, "to_session": sw.to_session}, source_kind="mcp-log",
                source=anchor.source, lines=[sw.line]), anchor, [anchor]))
        for x in calls + events:
            stream_meta[id(x)] = (info.server_dir, info.encoded_cwd, info.path)
        built_calls += calls
        built_events += events
        if shown is not None and info.path not in shown:
            continue  # analysed for the pairing only: not in the per-server summaries
        key = (info.encoded_cwd, info.server_dir)
        error_counts[key] += sum(1 for r in recs if r.key == "error")
        stderr_counts[key] += sum(1 for r in recs if r.category == "stderr")

    for p in parsed_debug:
        retries = file_retry_links(p)
        dispatch_by_line = pair_dispatch(p, retries)
        streams: dict[str, list[Rec]] = defaultdict(list)
        for r in p.mirror_recs:
            streams[r.stream].append(r)
        cwd_hint = cwd_by_session.get(p.info.session_id or "")
        for stream, recs in streams.items():
            raw = recs[0].raw_server or ""
            si = StreamInfo(raw, recs[0].server_dir, [raw], "debug-mirror", p.entrypoint_mode, cwd_hint=cwd_hint,
                            session_hint=p.info.session_id, process_starts=tuple(p.process_start_lines),
                            retry_links=retries)
            try:
                calls, events = analyze_stream(recs, si, policy)
            except Exception as exc:  # defensive: one bad file must not stop the run
                ev.warnings.append(f"failed to analyse debug mirror lines of {raw!r} in {p.info.path}: {exc}")
                continue
            for bc in calls:
                bc.model.dispatch = dispatch_by_line.get(bc.start.line)
                rnote = retry_dispatch_note(bc)
                if rnote:
                    bc.model.notes.append(rnote)
                twin = bc.start.xref
                if twin is not None:
                    # the MCP log has this call: carry debug-only facts over
                    lb = next((b for b in built_calls if b.start is twin), None)
                    if lb is not None:
                        lb.model.debug_copy = bc.start.source
                        lb.model.dispatch = bc.model.dispatch
                        if rnote and lb.retry_start is not None:
                            lb.model.notes.append(f"debug file {bc.start.source_path}: {rnote}")
                        if lb.end is None and bc.end is not None:
                            lb.model.outcome = bc.model.outcome
                            lb.model.duration = bc.model.duration
                            lb.model.end_source = bc.model.end_source
                            lb.model.end_timestamp = bc.model.end_timestamp
                            lb.end_ms = bc.end_ms
                            lb.model.notes.append("completion taken from the debug file (no MCP-log record)")
                    continue
                bc.model.notes.append("no MCP-log record of this call; reconstructed from debug mirror lines")
                stream_meta[id(bc)] = (bc.model.server_dir, enc(cwd_hint) if cwd_hint else None, p.info.path)
                built_calls.append(bc)
            for be in events:
                twin = be.anchor.xref
                if twin is not None:
                    lb = next((e for e in built_events if twin in e.recs), None)
                    if lb is not None and lb.model.debug_copy is None:
                        lb.model.debug_copy = be.anchor.source
                    continue
                stream_meta[id(be)] = (be.model.server_dir, enc(cwd_hint) if cwd_hint else None, p.info.path)
                built_events.append(be)
            if shown is not None and p.info.path not in shown:
                continue
            key = (enc(cwd_hint) if cwd_hint else None, recs[0].server_dir)
            error_counts[key] += sum(1 for r in recs if r.key == "error" and r.xref is None)
            stderr_counts[key] += sum(1 for r in recs if r.category == "stderr" and r.xref is None)
        if shown is None or p.info.path in shown:
            ev.debug_server_infos += p.server_infos
        ev.debug_files.append(p.info)

    # debug-file events that add evidence to the timeline
    for p in parsed_debug:
        for e, c in p.catalog_entries:
            evname = {"dbg.log_batch_dropped": "mcp-log-write-dropped",
                      "dbg.permission_denied": "permission-denied",
                      "dbg.tool_not_found_render": "tool-not-found",
                      "dbg.prior_unclean": "prior-session-unclean"}.get(c.id)
            if evname is None:
                continue
            src = f"{p.info.path}:{e.line}"
            spans = spans_for_message(c.mask, e.message, c)
            display, sens = apply_spans(e.message, spans, src, policy)
            f = output_fields(c, [] if policy.show else [(sp.start, sp.end) for sp in spans])
            tool = f.get("tool", "")
            server = ""
            if tool.startswith("mcp__") and "__" in tool[5:]:
                server = tool[5:].split("__", 1)[0]
            elif c.id == "dbg.permission_denied":
                continue  # native tools are out of scope
            summary = {
                "mcp-log-write-dropped": f"MCP-log write failed: {display}",
                "permission-denied": f"permission denied for {tool}",
                "tool-not-found": f"{tool} not found in render-time tools",
                "prior-session-unclean": f"prior session {f.get('session_id')} exited without cleanup",
            }[evname]
            ev.events.append(ServerEvent(
                event=evname, timestamp=e.timestamp, session_uuid=p.info.session_id, server=server or "-",
                server_dir=enc(server) if server else "", summary=summary, fields=f, sensitive=sens,
                source_kind="debug-file", source=src, lines=[e.line],
            ))

    # --- joins ------------------------------------------------------------------------
    log_sessions_by_server: dict[str, set[str]] = defaultdict(set)
    for _, recs in log_streams:
        for r in recs:
            if r.session_id:
                log_sessions_by_server[r.server_dir].add(r.session_id)
    for p in parsed_debug:
        for r in p.mirror_recs:
            if r.session_id:
                log_sessions_by_server[r.server_dir].add(r.session_id)
    if flt is not None:
        for sd, sids in flt.log_sessions_by_server.items():
            log_sessions_by_server[sd] |= sids
    join_calls(built_calls, tool_calls, transcript_sessions, log_sessions_by_server)

    ev.log_calls = [bc.model for bc in built_calls]
    ev.events = sorted([be.model for be in built_events] + ev.events, key=_event_order)

    # --- per-server summaries ----------------------------------------------------------
    summaries: dict[tuple[Optional[str], str], LogServerSummary] = {}
    recorded_urls: dict[tuple[Optional[str], str], list[tuple[str, Optional[str]]]] = defaultdict(list)

    def summ(key: tuple[Optional[str], str], server: str, cands: list[str]) -> LogServerSummary:
        if key not in summaries:
            disp, cc, status = names.resolve(key[1])
            summaries[key] = LogServerSummary(server=disp, server_dir=key[1], encoded_cwd=key[0],
                                              name_candidates=cc or cands, name_status=status)
        return summaries[key]

    def seen(s: LogServerSummary, ts: Optional[str]) -> None:
        if ts:
            if s.first_seen is None or _ts_key(ts) < _ts_key(s.first_seen):
                s.first_seen = ts
            if s.last_seen is None or _ts_key(ts) > _ts_key(s.last_seen):
                s.last_seen = ts

    def touch(s: LogServerSummary, ts: Optional[str], src: str, kind: str, cwd: Optional[str]) -> None:
        seen(s, ts)
        if kind not in s.sources:
            s.sources.append(kind)
        if kind == "mcp-log" and src not in s.log_files:
            s.log_files.append(src)
        if cwd and cwd not in s.cwds:
            s.cwds.append(cwd)

    for be in built_events:
        sd, ecwd, fpath = stream_meta.get(id(be), (be.model.server_dir, None, be.model.source))
        if shown is not None and fpath not in shown:
            continue
        s = summ((ecwd, sd), be.model.server, be.model.server_candidates)
        m = be.model
        touch(s, m.timestamp, fpath, m.source_kind, m.cwd)
        seen(s, m.end_timestamp)
        if m.event == "connect":
            s.connect_attempts += 1
            o = m.fields.get("outcome")
            if o == "connected":
                s.connect_ok += 1
            elif o == "failed":
                s.connect_failed += 1
            else:
                s.connect_no_outcome += 1
            t = m.fields.get("transport")
            if t and t not in s.transports:
                s.transports.append(t)
            u = m.fields.get("url")
            if u:
                if u not in s.log_urls:
                    s.log_urls.append(u)
                recorded_urls[(ecwd, sd)].append((u, _recorded_url(be)))
            ms = m.fields.get("connect_ms")
            if isinstance(ms, int):
                s.connect_ms_min = ms if s.connect_ms_min is None else min(s.connect_ms_min, ms)
                s.connect_ms_max = ms if s.connect_ms_max is None else max(s.connect_ms_max, ms)
            sv = m.fields.get("server_version")
            if sv and sv not in s.server_versions:
                s.server_versions.append(sv)
            code = m.fields.get("failure_code")
            if code and code not in s.failure_codes:
                s.failure_codes.append(code)
        elif m.event == "shutdown":
            s.shutdowns += 1
    for bc in built_calls:
        sd, ecwd, fpath = stream_meta.get(id(bc), (bc.model.server_dir, None, bc.model.source))
        if shown is not None and fpath not in shown:
            continue
        s = summ((ecwd, sd), bc.model.server, bc.model.server_candidates)
        touch(s, bc.model.start_timestamp, fpath, bc.model.source_kind, bc.model.cwd)
        seen(s, bc.model.end_timestamp)
        s.tool_calls += 1
        if bc.model.outcome == "failed":
            s.tool_failed += 1
        elif bc.model.outcome == "no completion record":
            s.tool_no_completion += 1
    for key, n in error_counts.items():
        if key in summaries:
            summaries[key].error_records += n
    for key, n in stderr_counts.items():
        if key in summaries:
            summaries[key].stderr_records += n
    for info, recs in log_streams:
        s = summaries.get((info.encoded_cwd, info.server_dir))
        if s is None or (shown is not None and info.path not in shown):
            continue
        if info.possibly_shared:
            s.possibly_shared = True
        for r in recs:  # "seen" spans every record, also those that belong to no event or call
            seen(s, r.timestamp)

    # attach to configured servers
    for s in summaries.values():
        for srv in servers:
            if enc(srv.name) != s.server_dir:
                continue
            scope_ok = (srv.scope == "user" or s.encoded_cwd is None or enc(srv.scope) == s.encoded_cwd
                        or srv.scope in s.cwds or srv.source_path.endswith(".mcp.json"))
            if scope_ok:
                srv.log_info.append(s)
                s.configured = True
                if srv.url:
                    pairs = recorded_urls.get((s.encoded_cwd, s.server_dir), [])
                    for u in s.log_urls:
                        if u not in srv.log_urls_matching_url and all(rec == srv.url for d, rec in pairs if d == u):
                            srv.log_urls_matching_url.append(u)
    ev.summaries = sorted(summaries.values(), key=lambda s: (s.encoded_cwd or "", s.server_dir))
    if flt is not None:
        _leave_out_other_sessions(ev, ids, shown, eff, log_streams, parsed_debug)
        if ev.cross_check is not None:
            ev.cross_check = _restrict_cross_check(ev.cross_check, all_log_recs, debug_recs, ids, eff, pair_session,
                                                   {f.path for f in ev.debug_files})
        flt.debug_files_kept = len(ev.debug_files)
        flt.debug_files_pairing_only = len(parsed_debug) - len(ev.debug_files)
    return ev


def _effective_sessions(log_streams) -> dict[int, Optional[str]]:
    """id(MCP-log record) -> the session it belongs to: its sessionId; the
    leading --continue record belongs to the session of the next record."""
    out: dict[int, Optional[str]] = {}
    for info, recs in log_streams:
        good = [r for r in recs if r.key != "invalid"]
        lead = good[0] if info.leading_single_record_session and len(good) > 1 else None
        for r in recs:
            out[id(r)] = good[1].session_id if r is lead else r.session_id
    return out


# Server events that describe the server process (its connection, transport,
# configuration and shutdown) rather than one session's activity. Under a
# session filter they are kept from every kept file, whichever session id
# their records carry (a /clear switch changes it within one process); the
# other events are kept for the selected sessions only.
PROCESS_EVENTS = frozenset({
    "connect", "shutdown", "transport-error", "session-switch", "reconnect", "list-changed", "capabilities",
    "stderr", "transport", "connection", "oauth", "config", "channel", "discovery-cache", "skills", "tool-schema",
})


def _leave_out_other_sessions(ev: LogEvidence, ids: set[str], shown: set[str], eff: dict[int, Optional[str]],
                              log_streams, parsed_debug) -> None:
    """Session filter: keep the log calls of the selected sessions, their
    events and the server process events of the files shown; list only the
    shown files, and in them only the records of the selected sessions and
    records without a session id (MCP logs) and the entries of the selected
    sessions (debug files). The rows kept carry no withheld value of
    another session's record (their text shows it withheld, see
    build_log_evidence). Everything else is left out and counted per file;
    of a file read for the pairing only all records are counted. The
    per-server summaries cover the shown files as a whole."""
    per_file: dict[str, FilteredFile] = {}
    own = {p.info.path: p.info.session_id for p in parsed_debug}  # a debug file's session (name or matched)

    def left_out(path: str, sid: Optional[str], what: str, n: int = 1) -> None:
        f = per_file.setdefault(path, FilteredFile(path=path, pairing_only=path not in shown))
        setattr(f, what, getattr(f, what) + n)
        if (sid or "") not in f.session_ids:
            f.session_ids.append(sid or "")

    calls = []
    for lc in ev.log_calls:
        if lc.session_id in ids:
            calls.append(lc)
        else:
            left_out(lc.source.rpartition(":")[0] or lc.source, lc.session_id, "log_calls")
    # the session a record belongs to, by the source of its withheld values
    record_session: dict[str, Optional[str]] = {}
    for _info, recs in log_streams:
        for r in recs:
            record_session[r.source] = eff.get(id(r))
    for p in parsed_debug:
        for r in p.mirror_recs:
            record_session[r.source] = eff.get(id(r.xref)) if r.xref is not None else r.session_id
    events = []
    for e in ev.events:
        path = e.source.rpartition(":")[0] or e.source
        process = e.event in PROCESS_EVENTS and path in shown and (path not in own or own[path] in ids)
        if e.session_uuid in ids or process:
            kept = []
            for item in e.sensitive:
                sid = record_session.get(item.source)
                if sid is None or sid in ids:
                    kept.append(item)
                else:
                    left_out(item.source.rpartition(":")[0] or item.source, sid, "sensitive_items")
            e.sensitive = kept
            events.append(e)
        else:
            left_out(path, e.session_uuid, "server_events")
    ev.log_calls, ev.events = calls, events

    for info, recs in log_streams:
        if info.path not in shown:
            for r in recs:
                left_out(info.path, eff.get(id(r)), "records")
            continue
        keep = [eff.get(id(r)) in ids or eff.get(id(r)) is None for r in recs]
        for r, k in zip(recs, keep):
            if not k:
                left_out(info.path, eff.get(id(r)), "records")
        info.entries = [x for x, k in zip(info.entries, keep) if k]
    for p in parsed_debug:
        if p.info.path not in shown:
            if p.info.mcp_entries:
                left_out(p.info.path, own.get(p.info.path), "records", len(p.info.mcp_entries))
            continue
        by_line = {r.line: r for r in p.mirror_recs}
        entries = []
        for x in p.info.mcp_entries:
            r = by_line.get(x.line) if x.mirror else None
            if r is not None:
                sid = eff.get(id(r.xref)) if r.xref is not None else r.session_id
            else:
                sid = own.get(p.info.path)
            if sid in ids:
                entries.append(x)
            else:
                left_out(p.info.path, sid, "records")
        p.info.mcp_entries = entries

    ev.mcp_log_files = [f for f in ev.mcp_log_files if f.path in shown]
    ev.debug_files = [f for f in ev.debug_files if f.path in shown]
    names = {f.path for f in ev.debug_files}
    ev.latest_links = [x for x in ev.latest_links
                       if x.path in names or x.resolves_to in names or x.identical_to in names]
    for cr in ev.cache_roots:
        cr.log_files = sum(1 for f in ev.mcp_log_files if f.cache_root == cr.path)
    for f in per_file.values():
        f.session_ids.sort()
    ev.filtered_out = sorted(per_file.values(), key=lambda f: (f.pairing_only, f.path))


def _restrict_cross_check(cc: CrossCheck, log_recs: list[Rec], debug_recs: list[Rec], ids: set[str],
                          eff: dict[int, Optional[str]], pair_session: dict[int, Optional[str]],
                          debug_paths: set[str]) -> CrossCheck:
    """The cross-check of the selected sessions: the MCP-log records of a
    selected session in scope, the mirror lines paired with them, and the
    unpaired mirror lines of a selected session's debug file. The pairing
    itself is that of the whole analysed set (an unfiltered run's)."""
    def mine(d: Rec) -> bool:
        return eff.get(id(d.xref)) in ids if d.xref is not None else d.session_id in ids

    sel_r = [r for r in log_recs if r.xref_status is not None and eff.get(id(r)) in ids]
    sel_d = [d for d in debug_recs if mine(d)]
    out = CrossCheck(debug_files=len(debug_paths), debug_mirror_lines=len(sel_d),
                     mcp_log_records_in_scope=len(sel_r),
                     context=[c for c in cc.context if c.split(": ", 1)[0] in debug_paths])
    offsets: Counter = Counter()
    last: dict[tuple[str, str], int] = {}
    for d in sel_d:
        r = d.xref
        if r is None:
            out.debug_only += 1
            continue
        out.matched += 1
        if d.xref_status == "identical":
            out.identical += 1
        elif d.xref_status == "redaction-only":
            out.redaction_only += 1
        elif d.xref_status == "error-object":
            out.error_object += 1
        else:
            out.differs += 1
        if r.ts is not None and d.ts is not None:
            offsets[r.ts - d.ts] += 1
        if pair_session.get(id(d)) and r.session_id and pair_session.get(id(d)) != r.session_id:
            out.session_mismatches += 1
        k = (d.stream, r.source_path)
        if k in last and r.line < last[k]:
            out.order_inversions += 1
        last[k] = max(last.get(k, 0), r.line)
    out.mcp_log_only = sum(1 for r in sel_r if r.xref_status == "mcp-log only")
    out.offset_histogram_ms = {str(k): v for k, v in sorted(offsets.items())}
    out.offsets_outside_0_5ms = sum(v for k, v in offsets.items() if not 0 <= k <= 5)
    rsrc, dsrc = {r.source for r in sel_r}, {d.source for d in sel_d}
    out.items = [it for it in cc.items
                 if (it.mcp_log_source in rsrc if it.mcp_log_source else it.debug_source in dsrc)]
    return out
