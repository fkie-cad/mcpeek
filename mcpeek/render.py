"""Rendering: rich tables, --json output, redaction, and report export.

Redaction (--redact) uses an ANCHORED, case-insensitive key regex so that
credential-shaped keys (accessToken, refreshToken, clientSecret) are
scrubbed while benign keys that merely contain the substring "token"
(input_tokens, output_tokens -- present on every assistant usage-stats
block) are left untouched. It also masks MCP server env and header values,
credential-shaped values in stdio command lines and headersHelper commands
(redact_args, redact_credentials_in_text), and the userinfo, query values
and fragment of every field whose value is a URL.

Values from the MCP log and the --debug file that can be secrets are handled
separately (sensitive.py): they are withheld unless --show-sensitive is given,
and every withheld value is listed with kind, size, hash prefix and source.

Every string taken from the evidence reaches a table as rich Text, never as
markup, so brackets or emoji codes in file content are shown literally.
"""
from __future__ import annotations

import html
import json
import re
import shlex
from pathlib import PurePath
from typing import Any, Iterable, Optional

from pydantic import BaseModel
from rich.console import Console
from rich.table import Table
from rich.text import Text

from .mcplog import format_duration, ts_ms
from .models import LogCall, ServerEvent, ToolCall

REDACTED = "[REDACTED]"

# Anchored + case-insensitive: matches accessToken/access_token,
# refreshToken/refresh_token, idToken/id_token, clientSecret/client_secret.
# Does NOT match input_tokens/output_tokens (plural, and wrong prefix word).
REDACT_KEY_RE = re.compile(r"^(?:(?:access|refresh|id)_?token|client_?secret)$", re.IGNORECASE)


_URL_VALUE_RE = re.compile(r"^\s*[A-Za-z][A-Za-z0-9+.\-]*://")
# Transcript content: documented as not changed by --redact.
_SUMMARY_KEYS = {"input_summary", "result_summary"}


def scrub(obj: Any) -> Any:
    """Recursively walk a JSON-ish structure for --redact: blank any value
    whose key matches REDACT_KEY_RE, mask MCP server env and header values
    and credential-shaped command-line values, and mask userinfo, query values
    and fragment of every value that is a URL.

    MCP server `env` and `headers` dicts are also a --redact category: their
    values often hold endpoints or tokens even though their key names (e.g.
    API_URL) never match REDACT_KEY_RE. `servers_to_jsonable()` handles this
    explicitly for the `servers` command; this generic walk handles it too,
    so any other JSON path that serializes a Server (e.g. `info --json`,
    which dumps the whole Case including nested servers) redacts it the same
    way.
    """
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and REDACT_KEY_RE.match(k):
                out[k] = REDACTED
            elif k in ("env", "headers") and isinstance(v, dict):
                out[k] = {ek: REDACTED for ek in v}
            elif k == "args" and isinstance(v, list) and all(isinstance(a, str) for a in v):
                out[k] = redact_args(v, True)
            elif k in ("command", "headers_helper") and isinstance(v, str):
                out[k] = redact_credentials_in_text(v)
            elif isinstance(v, str) and k not in _SUMMARY_KEYS and (k == "url" or _URL_VALUE_RE.match(v)):
                out[k] = redact_url(v, True)
            else:
                out[k] = scrub(v)
        return out
    if isinstance(obj, list):
        return [scrub(v) for v in obj]
    return obj


# Credential-shaped values in stdio command lines (--redact):
# a value after "=" or ":" following a name that contains one of these words,
# the value after a flag whose name contains one of them, the value after an
# HTTP authorization scheme word (Bearer, Basic, Digest, token, ...) in the
# same string or as the next argument, and well-known token formats.
_CRED_WORDS = r"(?:token|key|secret|password|passwd|auth|credential|bearer)"
_CRED_NAME = r"[A-Za-z0-9_.-]*" + _CRED_WORDS + r"[A-Za-z0-9_.-]*"
_SCHEME = r"(?:Bearer|Basic|Digest|Token|Negotiate|NTLM|DPoP|Bot|ApiKey)"
_ASSIGN_RE = re.compile(
    r"(?<![A-Za-z0-9])" + _CRED_NAME + r"""["']?\s*[=:]\s*["']?(?P<v>(?!""" + _SCHEME + r"""\b)[^\s;&|'",}]+)""",
    re.IGNORECASE,
)
_FLAG_RE = re.compile(r"^--?" + _CRED_NAME + r"$", re.IGNORECASE)
_SCHEME_RE = re.compile(r"\b" + _SCHEME + r"""\s+["']?(?P<v>[A-Za-z0-9._~+/=:-]+)""", re.IGNORECASE)
_ENDS_IN_SCHEME_RE = re.compile(r"(?:^|[\s:=\"'])" + _SCHEME + r"\s*$", re.IGNORECASE)
_TOKEN_SHAPES_RE = re.compile(
    r"(?<![A-Za-z0-9])(?P<v>"
    r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}"
    r"|xox[abposr]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|[rs]k_(?:live|test)_[A-Za-z0-9]{16,}"
    r"|(?:AKIA|ASIA)[A-Z0-9]{16}|AIza[0-9A-Za-z_-]{35}|npm_[A-Za-z0-9]{36}|hf_[A-Za-z0-9]{30,}"
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"
)


def _shell_tokens(text: str) -> list[tuple[int, int, str]]:
    """(start, end, unquoted text) of the whitespace-separated words of a
    command line; single and double quotes group words."""
    out = []
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        start, buf = i, []
        while i < n and not text[i].isspace():
            c = text[i]
            if c in "'\"":
                i += 1
                while i < n and text[i] != c:
                    if c == '"' and text[i] == "\\" and i + 1 < n:
                        i += 1
                    buf.append(text[i])
                    i += 1
                i += 1
            else:
                buf.append(c)
                i += 1
        out.append((start, min(i, n), "".join(buf)))
    return out


def _credential_spans(text: str, depth: int = 0) -> list[tuple[int, int]]:
    from .sensitive import url_spans

    spans = [(sp.start, sp.end) for sp in url_spans(text)]
    for rx in (_ASSIGN_RE, _SCHEME_RE, _TOKEN_SHAPES_RE):
        for m in rx.finditer(text):
            if m.group("v") != REDACTED:
                spans.append(m.span("v"))
    words = _shell_tokens(text)
    for (_, _, prev), (start, end, cur) in zip(words, words[1:]):
        if cur != REDACTED and ((_FLAG_RE.match(prev) and not cur.startswith("-")) or _ENDS_IN_SCHEME_RE.search(prev)):
            spans.append((start, end))
    if depth < 3:
        # a quoted word holding words of its own ("--secret X", "sh -c '...'"):
        # its values are masked inside the quotes, the flag names stay
        for start, end, cur in words:
            raw = text[start:end]
            if len(raw) > 2 and raw[0] == raw[-1] and raw[0] in "'\"" and raw[1:-1] == cur and " " in cur:
                spans += [(start + 1 + a, start + 1 + b) for a, b in _credential_spans(cur, depth + 1)]
    return spans


def redact_credentials_in_text(text: str) -> str:
    """Mask credential-shaped values in one command-line string (see above),
    plus URL userinfo, query values and fragments."""
    spans = _credential_spans(text)
    out, pos = [], 0
    for a, b in sorted(spans):
        if b <= pos:
            continue
        a = max(a, pos)
        out.append(text[pos:a])
        out.append(REDACTED)
        pos = b
    out.append(text[pos:])
    return "".join(out)


def redact_args(args: list[str], redact: bool) -> list[str]:
    """Under --redact, stdio args with credential-shaped values masked: the
    argument after a credential-named flag or after an authorization scheme
    word, and credential-shaped values inside each argument."""
    if not redact:
        return list(args)
    out = []
    for i, a in enumerate(args):
        prev = args[i - 1] if i else ""
        if (_FLAG_RE.match(prev) and not a.startswith("-")) or _ENDS_IN_SCHEME_RE.search(prev):
            out.append(REDACTED)
        else:
            out.append(redact_credentials_in_text(a))
    return out


def redact_env(env: dict[str, str], redact: bool) -> dict[str, str]:
    """MCP server env (and header) values are shown in full by default (they
    are part of the configuration under examination). Under --redact they are
    masked wholesale; key names are kept, since the names alone are not
    sensitive.
    """
    if not redact:
        return dict(env)
    return {k: REDACTED for k in env}


def redact_url(url: Optional[str], redact: bool) -> Optional[str]:
    """Under --redact, URL userinfo, query values and fragments of a configured
    server URL are masked (they can carry tokens); host, port and path stay."""
    if not redact or not url:
        return url
    from .sensitive import url_spans

    out, pos = [], 0
    for sp in sorted(url_spans(url), key=lambda x: x.start):
        out.append(url[pos:sp.start])
        out.append(REDACTED)
        pos = sp.end
    out.append(url[pos:])
    return "".join(out)


def model_to_jsonable(obj: Any, redact: bool = False) -> Any:
    if isinstance(obj, BaseModel):
        data = obj.model_dump(mode="json")
    elif isinstance(obj, (list, tuple)):
        return [model_to_jsonable(o, redact=redact) for o in obj]
    else:
        data = obj
    if redact:
        data = scrub(data)
    return data


def print_json(obj: Any, redact: bool = False) -> None:
    data = model_to_jsonable(obj, redact=redact)
    print(json.dumps(data, indent=2, sort_keys=False, default=str))


def print_json_raw(data: Any, redact: bool = False) -> None:
    if redact:
        data = scrub(data)
    print(json.dumps(data, indent=2, sort_keys=False, default=str))


# ---------------------------------------------------------------------------
# Session filter (--session / --project): JSON wrapping and text lines
# ---------------------------------------------------------------------------

# How a session filter applies to the configuration views: (applies, note)
FILTER_NOTES = {
    "servers": (True, "the configured servers (user scope, project scope, project .mcp.json) are listed in full, as "
                      "without the filter; the rows of servers not in the current configuration and the MCP log "
                      "details of every row (log_info) come from the MCP-log and --debug files shown for the "
                      "selected sessions; selected_sessions gives each server's calls in the selected sessions and "
                      "the connection attempts in the MCP-log files shown for them (of whichever session id)"),
    "oauth_clients": (False, "OAuth client registrations are configuration, not per session: listed in full"),
    "grants": (False, "permission grants and project .mcp.json approvals are configuration, not per session: "
                      "listed in full"),
}


def with_filter(case_filter, key: str, data: Any) -> Any:
    """Under a session filter, a list output becomes {"filter": ..., <key>: list};
    the configuration views also carry "filter_applies" and "filter_note".
    Without a filter the output is unchanged."""
    if case_filter is None:
        return data
    out: dict[str, Any] = {"filter": case_filter.model_dump(mode="json")}
    if key in FILTER_NOTES:
        out["filter_applies"], out["filter_note"] = FILTER_NOTES[key]
    out[key] = data
    return out


def _ids_text(ids: list[str], limit: int = 5) -> str:
    shown = ", ".join(ids[:limit])
    return shown + (f" and {len(ids) - limit} more" if len(ids) > limit else "")


def filter_lines(f) -> list[tuple[str, str]]:
    """(label, text) rows describing an active session filter."""
    given = "; ".join([f"--session {v}" for v in f.session_values] + [f"--project {v}" for v in f.project_values])
    rows = [("Session filter", f"{given} -> {len(f.session_ids)} session(s): {_ids_text(f.session_ids)}; "
                               f"{f.transcript_files_selected} of {f.transcript_files_total} transcript file(s) "
                               "(counted by file name)")]
    if f.mcp_log_files_total is not None:
        pairing = ""
        if f.mcp_log_files_pairing_only or f.debug_files_pairing_only:
            pairing = (f"; read for the pairing only, not shown: {f.mcp_log_files_pairing_only} MCP log and "
                       f"{f.debug_files_pairing_only} --debug file(s)")
        rows.append(("Shown by the filter", f"MCP log files {f.mcp_log_files_kept} of {f.mcp_log_files_total}; "
                                            f"--debug files {f.debug_files_kept} of {f.debug_files_total}{pairing}"))
        others = sorted({s for x in f.filtered_out_by_file for s in x.session_ids})
        text = (f"{f.log_calls_filtered_out} log call(s), {f.server_events_filtered_out} server event(s), "
                f"{f.records_filtered_out} log record(s) and {f.sensitive_items_filtered_out} withheld value(s) "
                "of other sessions")
        if others:
            text += " (" + _ids_text([s or "no session id" for s in others]) + ")"
        rows.append(("Left out by the filter", text))
    return rows


def filter_summary(f) -> str:
    """One line for the foot of a filtered view."""
    text = (f"session filter: {len(f.session_ids)} session(s) ({_ids_text(f.session_ids, 3)}), "
            f"{f.transcript_files_selected} of {f.transcript_files_total} transcript file(s)")
    if f.mcp_log_files_total is not None:
        text += (f"; MCP log files {f.mcp_log_files_kept} of {f.mcp_log_files_total}, --debug files "
                 f"{f.debug_files_kept} of {f.debug_files_total}; left out: {f.log_calls_filtered_out} log "
                 f"call(s), {f.server_events_filtered_out} server event(s), {f.records_filtered_out} log record(s) "
                 "of other sessions (see `info`)")
    return text


def left_out_text(x, root: Optional[str]) -> str:
    what = "read for the pairing only, not shown" if x.pairing_only else "left out"
    return (f"{_rel(x.path, root)}: {what}: {x.log_calls} log call(s), {x.server_events} server event(s), "
            f"{x.records} record(s), {x.sensitive_items} withheld value(s) of session(s) "
            + ", ".join(i or "(no session id)" for i in x.session_ids))


def _scope_fits(s, cwd: Optional[str]) -> bool:
    """A call or event recorded under ``cwd`` can belong to server row ``s``
    (the scope rule of the per-server MCP log summaries)."""
    from .mcplog import enc

    if s.scope == "user" or s.scope.startswith("(") or s.source_path.endswith(".mcp.json") or not cwd:
        return True
    return cwd == s.scope or enc(cwd) == enc(s.scope)


def selected_use(case, s) -> dict[str, int]:
    """Under a session filter: the server's calls in the selected sessions
    (transcript tool_use names, MCP-log calls) and the connection attempts in
    their kept MCP-log files."""
    from .mcplog import enc, hc

    name_hc, name_enc = hc(s.name), enc(s.name)
    conns = [e for e in case.server_events
             if e.event == "connect" and e.server_dir == name_enc and _scope_fits(s, e.cwd)]
    return {
        "transcript_calls": sum(1 for c in case.tool_calls
                                if c.is_mcp and c.mcp_server == name_hc and _scope_fits(s, c.cwd)),
        "log_calls": sum(1 for lc in case.log_calls if lc.server_dir == name_enc and _scope_fits(s, lc.cwd)),
        "connects": len(conns),
        "connected": sum(1 for e in conns if e.fields.get("outcome") == "connected"),
    }


def _selected_use_text(u: dict[str, int]) -> str:
    parts = []
    if u["transcript_calls"] or u["log_calls"]:
        parts.append(f"called: {u['transcript_calls']} transcript, {u['log_calls']} MCP-log call(s)")
    if u["connects"]:
        parts.append(f"connects {u['connects']} ({u['connected']} connected)")
    return "; ".join(parts) or "-"


def servers_to_jsonable(servers, redact: bool, case=None) -> list[dict]:
    """Servers need env and header value redaction even though their key
    names never match the credential-key regex used by scrub() -- env and
    headers are their own --redact category. Under a session filter each
    server also carries "selected_sessions" (see selected_use)."""
    out = []
    for s in servers:
        d = s.model_dump(mode="json")
        if case is not None and case.filter is not None:
            d["selected_sessions"] = selected_use(case, s)
        d["env"] = redact_env(s.env, redact)
        d["headers"] = redact_env(s.headers, redact)
        d["url"] = redact_url(s.url, redact)
        if s.oauth is not None:
            # scrub(d) below masks credential-shaped keys in it (see _oauth_shown)
            d["oauth"] = {k: (redact_url(v, redact) if isinstance(v, str) else v) for k, v in s.oauth.items()}
        if redact:
            d = scrub(d)
        out.append(d)
    return out


def _oauth_shown(oauth: dict, redact: bool) -> dict:
    """The configured oauth object as output: as stored by default; under
    --redact URL values follow the URL rules and the value of a
    credential-shaped key (clientSecret, ...) is masked, at any depth -- the
    same scrub() the JSON output applies, so tables, reports and JSON agree."""
    d = {k: (redact_url(v, redact) if isinstance(v, str) else v) for k, v in oauth.items()}
    return scrub(d) if redact else d


def _rel(path: Optional[str], root: Optional[str]) -> str:
    """Shorten a path for tables: relative to the target root when inside it."""
    if not path:
        return "-"
    if root:
        r = root.rstrip("/") + "/"
        if path.startswith(r):
            return path[len(r):]
    return path


# C0 and C1 control characters other than newline and tab (ESC, BEL, CR,
# ...) in human-readable output are shown as visible escapes, so evidence
# text cannot drive the terminal; JSON output keeps the exact value.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def visible(text: str) -> str:
    return _CONTROL_RE.sub(lambda m: f"\\x{ord(m.group()):02x}", text)


def _cell(text: Any) -> Text:
    """Evidence-derived text for a table cell, title or line: plain Text,
    never parsed as rich markup or emoji codes."""
    return Text("" if text is None else visible(str(text)))


def _say(console: Console, text: str, style: Optional[str] = None) -> None:
    console.print(Text(visible(text), style=style or ""))


# Column helpers: timestamps and ids never wrap; other columns fold, so that
# a narrow console squeezes them instead of cutting a timestamp or id.
def _ts_column(table: Table, header: str) -> None:
    table.add_column(header, no_wrap=True, min_width=24)


def _id_column(table: Table, header: str, width: int, **kw: Any) -> None:
    table.add_column(header, no_wrap=True, min_width=width, **kw)


def _col(table: Table, header: str, **kw: Any) -> None:
    kw.setdefault("overflow", "fold")
    table.add_column(header, **kw)


# ---------------------------------------------------------------------------
# Native-tool visibility toggle: id-stitch only, never tool-name.
# A tool_call's is_spawn/is_mcp flags were already computed purely from the
# subagent meta.json toolUseId join in parse.py -- this function only
# filters the already-correct rows for display.
# ---------------------------------------------------------------------------


def select_tool_calls_for_view(calls: Iterable[ToolCall], mode: str) -> list[ToolCall]:
    calls = list(calls)
    if mode == "all":
        return calls
    if mode == "mcp-only":
        return [c for c in calls if c.is_mcp]
    # default: MCP calls + subagent-spawn rows as first class
    return [c for c in calls if c.is_mcp or c.is_spawn]


def native_tool_counts(calls: Iterable[ToolCall]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for c in calls:
        if c.is_mcp or c.is_spawn:
            continue
        counts[c.tool_name] = counts.get(c.tool_name, 0) + 1
    return counts


def log_call_row(lc: LogCall) -> ToolCall:
    """A log call without a (unique) transcript counterpart, as a timeline row.

    The MCP log cannot tell a delegated (sub-agent) call from a direct one and
    has no transcript result, so depth, sidechain and the transcript-result
    fields are None; the log outcome is in ``log``. ``tool_use_id`` is None
    unless a debug file supplied it."""
    from .models import ToolCallLogInfo

    kind = "log-call-ambiguous" if lc.join_status == "ambiguous" else "log-only-call"
    server = lc.server
    return ToolCall(
        row_kind=kind,
        tool_use_id=(lc.dispatch.tool_use_id if lc.dispatch else None) or None,
        tool_name=f"mcp__{server}__{lc.tool}",
        is_mcp=True,
        mcp_server=server,
        mcp_tool=lc.tool,
        timestamp=lc.start_timestamp,
        session_uuid=lc.session_id or "",
        cwd=lc.cwd,
        is_sidechain=None,
        spawn_depth=None,
        result_found=None,
        result_is_error=None,
        source_path=lc.source,
        log=ToolCallLogInfo(
            status="log-only" if kind == "log-only-call" else "ambiguous",
            source=lc.source, source_kind=lc.source_kind, outcome=lc.outcome, duration=lc.duration,
            end_timestamp=lc.end_timestamp, timestamp_delta_ms=lc.timestamp_delta_ms,
            heartbeats_s=list(lc.heartbeats_s), dispatch=lc.dispatch,
            candidate_tool_use_ids=list(lc.candidate_tool_use_ids), notes=list(lc.notes),
        ),
    )


def chronological(rows: list) -> list:
    """Rows in timestamp order across all sessions (ISO offsets normalized to
    UTC); equal timestamps keep session order, then their original order. Rows
    without a usable timestamp come last."""
    def key(item):
        i, r = item
        ms = ts_ms(r.timestamp)
        rank = 0 if ms is not None else (1 if r.timestamp else 2)
        return (rank, ms or 0, r.timestamp or "", getattr(r, "session_uuid", None) or "", i)

    return [r for _, r in sorted(enumerate(rows), key=key)]


def timeline_rows(case, mode: str, server_events: bool = True) -> list[BaseModel]:
    rows: list[BaseModel] = list(select_tool_calls_for_view(case.tool_calls, mode))
    rows += [log_call_row(lc) for lc in case.log_calls if lc.join_status != "matched"]
    if server_events and mode != "mcp-only":
        rows += list(case.server_events)
    return chronological(rows)


# ---------------------------------------------------------------------------
# Table renderers
# ---------------------------------------------------------------------------


def _log_summary_cell(info_list) -> str:
    if not info_list:
        return "-"
    parts = []
    for ls in info_list:
        p = []
        where = ", ".join(ls.cwds) or ls.encoded_cwd or ""
        if where:
            p.append(f"cwd {where}")
        p.append(f"files {len(ls.log_files)}" + (" + debug-only" if "debug-mirror" in ls.sources else ""))
        p.append(f"connects {ls.connect_ok} ok / {ls.connect_failed} failed"
                 + (f" / {ls.connect_no_outcome} no outcome" if ls.connect_no_outcome else ""))
        if ls.transports:
            p.append("transport " + ",".join(ls.transports))
        if ls.connect_ms_min is not None:
            rng = f"{ls.connect_ms_min}" if ls.connect_ms_min == ls.connect_ms_max else f"{ls.connect_ms_min}-{ls.connect_ms_max}"
            p.append(f"connect {rng} ms")
        if ls.server_versions:
            p.append("serverVersion " + ", ".join(ls.server_versions))
        if ls.failure_codes:
            p.append("failure codes " + ", ".join(ls.failure_codes))
        p.append(f"calls {ls.tool_calls} ({ls.tool_failed} failed, {ls.tool_no_completion} no completion)")
        p.append(f"error records {ls.error_records}")
        p.append(f"shutdowns {ls.shutdowns}")
        if ls.name_status == "ambiguous":
            p.append("folder shared by names: " + ", ".join(ls.name_candidates))
        if ls.possibly_shared:
            p.append(f"possibly shared by servers whose names sanitize to {ls.server_dir}")
        p.append(f"seen {ls.first_seen} .. {ls.last_seen}")
        parts.append("; ".join(p))
    return "\n".join(parts)


def _log_urls(s) -> list[str]:
    """Remote URLs recorded in the server's MCP logs, as displayed (userinfo,
    query values and fragment withheld unless --show-sensitive), without the
    ones whose recorded value equals the configured URL."""
    out: list[str] = []
    for ls in s.log_info:
        for u in ls.log_urls:
            if u not in out and u not in s.log_urls_matching_url:
                out.append(u)
    return out


def _command_or_url(s, redact: bool, sep: str = "\n") -> str:
    """Configured URL or command line, plus the URLs recorded in the MCP log
    that differ from it (labelled "from MCP log"; both labelled when both are
    shown)."""
    logged = [f"{u} (from MCP log)" for u in _log_urls(s)]
    url = redact_url(s.url, redact)
    cmd = ""
    if s.command:
        command = redact_credentials_in_text(s.command) if redact else s.command
        # shell quoting keeps argument boundaries visible (JSON keeps the list)
        cmd = " ".join(a if a == REDACTED else shlex.quote(a) for a in [command] + redact_args(s.args, redact))
    if url and cmd:
        # both configured: both shown, labelled, the one the transport uses first
        pair = [("command", cmd), ("url", url)]
        if s.transport.value != "stdio":
            pair.reverse()
        configured = [f"{k}: {v}" for k, v in pair]
    else:
        configured = [url or cmd] if (url or cmd) else []
    if configured and logged:
        configured = [c + " (configured)" for c in configured]
    return sep.join(configured + logged)


def _headers_text(s, redact: bool, sep: str = "\n") -> str:
    """Configured headers (names always, values as stored unless --redact)
    and the headersHelper command."""
    lines = [f"{k}: {v}" for k, v in redact_env(s.headers, redact).items()]
    if s.headers_helper:
        helper = redact_credentials_in_text(s.headers_helper) if redact else s.headers_helper
        lines.append(f"headersHelper: {helper}")
    return sep.join(lines) if lines else "-"


def _oauth_text(s, redact: bool, sep: str = "\n") -> str:
    """The configured oauth object (clientId, callbackPort, ...), as in the
    JSON output: shown as stored by default; under --redact URL values follow
    the URL rules (userinfo, query values and fragment masked) and
    credential-shaped keys (clientSecret, client_secret, ...) are masked."""
    if s.oauth is None:
        return "-"
    lines = []
    for k, v in _oauth_shown(s.oauth, redact).items():
        shown = v if isinstance(v, str) else json.dumps(v)
        lines.append(f"{k}: {shown}")
    return sep.join(lines) if lines else "(empty)"


def _transport_text(s) -> str:
    """Transport of a server row. A configured type that is not a known
    transport is shown as written."""
    if s.type_raw is not None:
        return f'{s.transport.value} (type "{visible(s.type_raw)}")'
    return s.transport.value


# Below this console width the servers view is printed as one field/value
# block per server.
_SERVERS_WIDE_MIN = 140


def render_servers(console: Console, servers, redact: bool, case=None) -> None:
    table = Table(title="MCP Servers", show_lines=True, expand=True)
    table.add_column("Server", overflow="fold", ratio=1)
    table.add_column("Scope", overflow="fold", ratio=2)
    table.add_column("Transport", overflow="fold", ratio=1)
    table.add_column("Command / URL", overflow="fold", ratio=3)
    table.add_column("Env", overflow="fold", ratio=2)
    table.add_column("Headers", overflow="fold", ratio=2)
    oauth = any(s.oauth is not None for s in servers)
    if oauth:
        table.add_column("OAuth config", overflow="fold", ratio=2)
    table.add_column("Debug (--debug file)", overflow="fold", ratio=2)
    table.add_column("MCP log", overflow="fold", ratio=4)
    flt = case.filter if case is not None else None
    if flt is not None:
        table.add_column("Selected session(s)", overflow="fold", ratio=2)
    cards = []
    for s in servers:
        cmd_or_url = _command_or_url(s, redact)
        env = redact_env(s.env, redact)
        env_str = "\n".join(f"{k}={v}" for k, v in env.items()) if env else "-"
        if s.debug_info:
            info = s.debug_info[-1]
            version = (f"{info.server_version_name}/{info.server_version_version}" if info.server_version_name
                       else (info.server_version_text or "-"))
            dbg = f"proto={info.negotiated_protocol_version or '-'} server={version}"
            if info.runtime_arm:
                dbg += f" arm={info.runtime_arm}"
        else:
            dbg = "-"
        card = [("Server", s.name), ("Scope", s.scope), ("Transport", _transport_text(s)),
                ("Command / URL", cmd_or_url or "-"), ("Env", env_str), ("Headers", _headers_text(s, redact)),
                *([("OAuth config", _oauth_text(s, redact))] if oauth else []),
                ("Debug (--debug file)", dbg), ("MCP log", _log_summary_cell(s.log_info))]
        if flt is not None:
            card.append(("Selected session(s)", _selected_use_text(selected_use(case, s))))
        cards.append(card)
        table.add_row(*(_cell(v) for _, v in card))
    if console.width >= _SERVERS_WIDE_MIN:
        console.print(table)
    else:
        _cards(console, "MCP Servers", cards)
    if flt is not None:
        _say(console, filter_summary(flt), "dim")
        _say(console, "session filter: " + FILTER_NOTES["servers"][1].replace("selected_sessions gives",
                                                                                "the Selected session(s) column gives"),
             "dim")


def render_tools(console: Console, tools) -> None:
    table = Table(title="MCP Tools (observed)")
    _col(table, "Server")
    _col(table, "Tool")
    _col(table, "Calls (transcripts)", justify="right")
    _col(table, "Sessions", justify="right")
    _col(table, "Calls (MCP log)", justify="right")
    _col(table, "Failed (MCP log)", justify="right")
    for t in tools:
        server = t.server_name
        if t.log_folder:
            server = f"{t.log_folder} (MCP-log folder shared by {', '.join(t.server_candidates)})"
        table.add_row(_cell(server), _cell(t.tool_name), str(t.call_count), str(len(t.sessions)),
                      str(t.log_call_count), str(t.log_failed_count))
    console.print(table)


# Below this console width the sessions table stacks its columns (session id
# over cwd, first over last, counts in one cell), so that ids and timestamps
# stay whole at 80 columns.
_SESSIONS_WIDE_MIN = 148


def render_sessions(console: Console, sessions) -> None:
    table = Table(title="Sessions")
    if console.width >= _SESSIONS_WIDE_MIN:
        _id_column(table, "Session UUID", 36)
        _col(table, "cwd(s)")
        _ts_column(table, "First")
        _ts_column(table, "Last")
        _col(table, "Msgs", justify="right")
        _col(table, "Tool calls", justify="right")
        _col(table, "MCP calls", justify="right")
        _col(table, "Subagents", justify="right")
        for s in sessions:
            table.add_row(
                _cell(s.session_uuid),
                _cell(", ".join(sorted(s.cwds)) or "-"),
                _cell(s.first_timestamp or "-"),
                _cell(s.last_timestamp or "-"),
                str(s.message_count),
                str(s.tool_call_count),
                str(s.mcp_tool_call_count),
                str(s.subagent_count),
            )
    else:
        table.pad_edge = False
        _col(table, "Session UUID / cwd(s)")
        table.add_column("First / last", no_wrap=True, min_width=24)
        table.add_column("Counts", no_wrap=True)
        for s in sessions:
            table.add_row(
                _cell(s.session_uuid + "\n" + (", ".join(sorted(s.cwds)) or "-")),
                _cell(f"{s.first_timestamp or '-'}\n{s.last_timestamp or '-'}"),
                _cell(f"msgs {s.message_count}\ntools {s.tool_call_count}\nmcp {s.mcp_tool_call_count}\n"
                      f"subagents {s.subagent_count}"),
            )
    console.print(table)


def _size_text(n: int) -> str:
    size, unit = float(n), "B"
    for larger in ("KiB", "MiB", "GiB"):
        if size < 1024:
            break
        size, unit = size / 1024, larger
    return f"{n} B" if unit == "B" else f"{size:.1f} {unit}"


_QUICK_WIDE_MIN = 170


def render_quick_sessions(console: Console, rows: list[dict], total: int, flt=None) -> None:
    """`sessions --quick`: one row per transcript, newest last activity first."""
    table = Table(title="Sessions (quick: first and last records, file size and companion folder names)")

    def sid(r: dict) -> str:
        name = PurePath(r["transcript_path"]).name
        return r["session_id"] + (f"\nfile name {name}" if r["file_name_differs"] else "")

    def count(v: Optional[int]) -> str:
        return "-" if v is None else str(v)

    if console.width >= _QUICK_WIDE_MIN:
        _id_column(table, "Session", 36)
        _col(table, "Project folder")
        _col(table, "cwd")
        _ts_column(table, "First")
        _ts_column(table, "Last")
        _col(table, "Size", justify="right")
        _col(table, "Sub-agents", justify="right")
        _col(table, "Spilled", justify="right")
        for r in rows:
            table.add_row(_cell(sid(r)), _cell(r["project_dir"]), _cell(r["cwd"] or "-"),
                          _cell(r["first_timestamp"] or "-"), _cell(r["last_timestamp"] or "-"),
                          _size_text(r["size_bytes"]), count(r["subagent_sidecars"]), count(r["spilled_results"]))
    else:
        table.pad_edge = False
        _col(table, "Session / project folder / cwd")
        table.add_column("First / last", no_wrap=True, min_width=24)
        table.add_column("Size, sub-agents, spilled", no_wrap=True)
        for r in rows:
            table.add_row(_cell(f"{sid(r)}\n{r['project_dir']}\n{r['cwd'] or '-'}"),
                          _cell(f"{r['first_timestamp'] or '-'}\n{r['last_timestamp'] or '-'}"),
                          _cell(f"{_size_text(r['size_bytes'])}\nsub-agents {count(r['subagent_sidecars'])}\n"
                                f"spilled {count(r['spilled_results'])}"))
    console.print(table)
    shown = f"{len(rows)} of {total}" if len(rows) != total else str(total)
    _say(console, f"{shown} transcript(s); first/last: timestamps of the first and last records that carry one "
                  "(at most 8 MiB read from each end, lines over 1 MiB skipped); sub-agents: agent-*.meta.json in "
                  "<session>/subagents/; spilled: files in <session>/tool-results/", "dim")
    if flt is not None:
        _say(console, filter_summary(flt), "dim")


def _depth_prefix(depth: int) -> str:
    return ("  " * depth) + ("└─ " if depth > 0 else "")


_RETRY_NOTE = "retried after session recovery"


def _retried(notes) -> bool:
    """A log call retried after session recovery (one call, two attempts; the
    attempt details are in the notes of the JSON output)."""
    return any(n.startswith(_RETRY_NOTE) for n in notes)


def _log_cell(c: ToolCall) -> str:
    if not c.is_mcp or c.log is None:
        return "-"
    lg = c.log
    if lg.status in ("matched", "log-only", "ambiguous") and lg.source:
        parts = [lg.status if lg.status != "matched" else "matched"]
        if lg.method == "toolUseId from debug file":
            parts[0] += " (toolUseId)"
        parts.append(lg.outcome or "")
        if lg.duration:
            parts.append(format_duration(lg.duration))
        if lg.heartbeats_s:
            parts.append(f"still running at {', '.join(str(h) for h in lg.heartbeats_s)}s")
        if lg.source_kind == "debug-mirror":
            parts.append("from debug file")
        if lg.call_offset_ms is not None:
            parts.append(f"log Calling {lg.call_offset_ms:+d} ms after tool_use")
        if lg.dispatch and lg.dispatch.permission_decision_ms is not None:
            parts.append(f"permissionDecisionMs {lg.dispatch.permission_decision_ms}")
        if c.row_kind == "tool-call":
            if _retried(lg.notes):
                parts.append(_RETRY_NOTE)
            parts.append("log " + "/".join(lg.source.rsplit("/", 2)[-2:]))
        else:
            parts.extend(lg.notes)
            if lg.candidate_tool_use_ids:
                parts.append("candidate tool_use ids: " + ", ".join(lg.candidate_tool_use_ids))
        return "; ".join(p for p in parts if p)
    if lg.status == "ambiguous":
        return f"ambiguous ({len(lg.candidate_sources)} log calls fit)"
    if lg.status == "no log record":
        if lg.log_file_for_session:
            return "no log record (MCP log of this server has this session)"
        return "no log record"
    return lg.status


def _spill_note(c: ToolCall, root: Optional[str]) -> str:
    """Short note for a call whose result was spilled to tool-results/."""
    if not c.spill_path:
        return ""
    if c.spill_path.startswith("UNRESOLVED:"):
        return f"spilled: {c.spill_path[len('UNRESOLVED:'):]} (file not found)"
    if c.spill_path.startswith("OUTSIDE:"):
        return f"spilled: {c.spill_path[len('OUTSIDE:'):]} (outside the target, not resolved)"
    return f"spilled: {_rel(c.spill_path, root)}"


# Below this console width the timeline (and the record tables of `logs`)
# stack their columns, so that timestamps and ids stay whole and the other
# columns keep a readable width.
_TIMELINE_WIDE_MIN = 140
_RECORDS_WIDE_MIN = 120


def render_timeline(console: Console, case, mode: str, server_events: bool = True) -> None:
    calls = case.tool_calls
    rows = timeline_rows(case, mode, server_events)
    root = case.target_root
    wide = console.width >= _TIMELINE_WIDE_MIN
    table = Table(title=f"Timeline ({mode}, timestamp order)")
    if wide:
        _ts_column(table, "Timestamp")
        _id_column(table, "Session", 8)
        _col(table, "Depth", justify="right")
        _col(table, "Tool / event")
        _col(table, "Kind")
        _col(table, "Result")
        _col(table, "Denied")
        _col(table, "MCP log / debug")
        _col(table, "Source")
    else:
        table.add_column("Timestamp / session / depth", no_wrap=True, min_width=24)
        _col(table, "Tool / event (kind, result, denied)", ratio=2)
        _col(table, "MCP log / debug; source", ratio=3)

    def add(ts: Optional[str], session: str, depth: str, label: str, kind: str, result: str, denied: str,
            log: str, source: str) -> None:
        if wide:
            table.add_row(_cell(ts or "-"), _cell(session), depth, _cell(label), kind, _cell(result), _cell(denied),
                          _cell(log), _cell(source))
        else:
            what = f"{kind}; result {result}" + (f"; denied {denied}" if denied != "-" else "")
            table.add_row(_cell(f"{ts or '-'}\n{session}" + (f"\ndepth {depth}" if depth != "-" else "")),
                          _cell(f"{label}\n{what}"), _cell(f"{log}\n{source}"))

    for r in rows:
        if isinstance(r, ServerEvent):
            add(r.timestamp, (r.session_uuid or "-")[:8], "-", f"{r.server}: {r.event}", "server-event", "-", "-",
                r.summary, _rel(r.source, root) + (f" (debug copy {_rel(r.debug_copy, root)})" if r.debug_copy else ""))
            continue
        c = r
        if c.row_kind == "log-only-call":
            kind = "log-only"
        elif c.row_kind == "log-call-ambiguous":
            kind = "log-ambiguous"
        elif c.is_spawn:
            kind = "SPAWN"
        elif c.is_mcp:
            kind = "mcp"
        else:
            kind = "native"
        tool_label = f"{c.mcp_server}__{c.mcp_tool}" if c.is_mcp else c.tool_name
        if c.row_kind != "tool-call":
            result = c.log.outcome if c.log else "-"
        else:
            result = "error" if c.result_is_error else ("ok" if c.result_found else "no-result")
        denied = c.denial_kind.value if c.denied and c.denial_kind else ("yes" if c.denied else "-")
        spill = _spill_note(c, root)
        add(c.timestamp, (c.session_uuid or "-")[:8], "-" if c.spawn_depth is None else str(c.spawn_depth),
            _depth_prefix(c.spawn_depth or 0) + tool_label, kind, result, denied, _log_cell(c),
            _rel(c.source_path, root) + (f"\n{spill}" if spill else ""))
    console.print(table)
    if mode == "default":
        native = native_tool_counts(calls)
        if native:
            summary = ", ".join(f"{k}: {v}" for k, v in sorted(native.items()))
            _say(console, f"native tool calls (counts only): {summary}", "dim")


def render_credentials(console: Console, oauth_clients, redact: bool = False) -> None:
    if console.width < _SERVERS_WIDE_MIN:
        _cards(console, "MCP OAuth Credentials", [
            [("Server", c.server_name), ("Server URL", redact_url(c.server_url, redact) or "-"),
             ("Client ID kind", c.client_id_kind.value), ("Client ID", redact_url(c.client_id, redact) or "-"),
             ("Issuer", redact_url(c.issuer, redact) or "-"), ("Redirect URI", redact_url(c.redirect_uri, redact) or "-"),
             ("Access token?", "yes" if c.has_access_token else "no"),
             ("Refresh token?", "yes" if c.has_refresh_token else "no")] for c in oauth_clients])
        return
    table = Table(title="MCP OAuth Credentials")
    _col(table, "Server")
    _col(table, "Server URL")
    _col(table, "Client ID kind")
    client_ids = [redact_url(c.client_id, redact) or "-" for c in oauth_clients]
    if all(len(x) <= 40 for x in client_ids):  # ids (UUIDs) whole; URLs (CIMD) fold
        _id_column(table, "Client ID", 9)
    else:
        _col(table, "Client ID")
    _col(table, "Issuer")
    _col(table, "Redirect URI")
    _col(table, "Access token?")
    _col(table, "Refresh token?")
    for c, cid in zip(oauth_clients, client_ids):
        table.add_row(
            _cell(c.server_name),
            _cell(redact_url(c.server_url, redact) or "-"),
            c.client_id_kind.value,
            _cell(cid),
            _cell(redact_url(c.issuer, redact) or "-"),
            _cell(redact_url(c.redirect_uri, redact) or "-"),
            "yes" if c.has_access_token else "no",
            "yes" if c.has_refresh_token else "no",
        )
    console.print(table)


_APPROVAL_TEXT = {"mcpjson-enabled": "enabled", "mcpjson-disabled": "disabled",
                  "mcpjson-enable-all": "enable all project .mcp.json servers"}


def render_grants(console: Console, grants, root: Optional[str] = None) -> None:
    table = Table(title="Permission Grants")
    _col(table, "Tool")
    _col(table, "MCP?")
    _col(table, "Server")
    _col(table, "Scope")
    _col(table, "Source")
    noted = any(g.note for g in grants if g.kind == "permission-allow")
    if noted:
        _col(table, "Note")
    approvals = []
    for g in grants:
        if g.kind != "permission-allow":
            approvals.append(g)
            continue
        table.add_row(_cell(g.tool_name), "yes" if g.is_mcp else "no", _cell(g.mcp_server or "-"), _cell(g.scope),
                      _cell(_rel(g.source_path, root)), *([_cell(g.note or "")] if noted else []))
    console.print(table)
    if approvals:
        t = Table(title="Project .mcp.json server approvals")
        _col(t, "Setting")
        _col(t, "Server")
        _col(t, "Decision")
        _col(t, "Scope")
        _col(t, "Source")
        for g in approvals:
            decision = _APPROVAL_TEXT.get(g.kind, g.kind)
            if g.kind == "mcpjson-enable-all":
                decision += f": {'true' if g.value else 'false'}"
            t.add_row(_cell(g.field), _cell(g.mcp_server or "-"), _cell(decision), _cell(g.scope),
                      _cell(_rel(g.source_path, root)))
        console.print(t)


def log_counts(case) -> dict[str, int]:
    lc = case.log_calls
    mcp_calls = [c for c in case.tool_calls if c.is_mcp]
    return {
        "log_calls": len(lc),
        "log_calls_matched": sum(1 for c in lc if c.join_status == "matched"),
        "log_calls_matched_by_tool_use_id": sum(1 for c in lc if c.join_method == "toolUseId from debug file"),
        "log_calls_ambiguous": sum(1 for c in lc if c.join_status == "ambiguous"),
        "log_calls_log_only": sum(1 for c in lc if c.join_status == "unmatched"),
        "log_calls_from_debug_only": sum(1 for c in lc if c.source_kind == "debug-mirror"),
        "transcript_mcp_calls": len(mcp_calls),
        "transcript_mcp_calls_no_log_record": sum(1 for c in mcp_calls if c.log and c.log.status == "no log record"),
        "transcript_mcp_calls_ambiguous": sum(1 for c in mcp_calls if c.log and c.log.status == "ambiguous"),
        "sensitive_items_withheld": 0 if case.sensitive_values_shown else (
            sum(f.sensitive_item_count for f in case.mcp_log_files)
            + sum(f.sensitive_item_count for f in case.debug_files)) if case.filter is None else (
            # under a session filter: the values in the records listed (see logevidence)
            sum(len(r.sensitive) for f in case.mcp_log_files for r in f.entries)
            + sum(len(x.sensitive) for f in case.debug_files for x in f.mcp_entries)),
    }


def _home_text(case) -> str:
    return f"{case.home} ({case.home_source})" if case.home else case.home_source


def _projects_text(case) -> str:
    """Project paths found in the target, counted as in the HOME row: paths
    below HOME found as folders, and a path that is HOME itself (the target
    root) named separately."""
    from .loader import path_below

    found = [p for p in case.projects if p.in_target]
    at_home = sum(1 for p in found if case.home and path_below(p.path, case.home) == ())
    missing = sum(1 for p in case.projects if p.target_path is not None and not p.in_target)
    outside = sum(1 for p in case.projects if p.target_path is None)
    return (f"{len(case.projects)} (below HOME: {len(found) - at_home} found in the target, {missing} "
            f"not found; {at_home} HOME itself (the target root); {outside} not inside HOME or HOME unknown)")


def render_info(console: Console, case) -> None:
    table = Table(title="Case Overview", show_header=False)
    table.add_column("Field", style="bold")
    _col(table, "Value")
    table.add_row("Target root", _cell(case.target_root))
    table.add_row("HOME on the examined host", _cell(_home_text(case)))
    table.add_row("Project paths", _projects_text(case))
    if case.filter is not None:
        for label, text in filter_lines(case.filter):
            table.add_row(label, _cell(text))
    table.add_row("Servers", str(len(case.servers)))
    table.add_row("Tools observed", str(len(case.tools)))
    table.add_row("Sessions", str(len(case.sessions)))
    table.add_row("Subagents", str(len(case.subagents)))
    table.add_row("Tool calls (total)", str(len(case.tool_calls)))
    table.add_row("MCP tool calls", str(sum(1 for c in case.tool_calls if c.is_mcp)))
    table.add_row("OAuth clients", str(len(case.oauth_clients)))
    dcr = sum(1 for c in case.oauth_clients if c.client_id_kind.value == "dcr")
    cimd = sum(1 for c in case.oauth_clients if c.client_id_kind.value == "cimd")
    table.add_row("  of which DCR / CIMD", f"{dcr} / {cimd}")
    table.add_row("Grants", str(len(case.grants)))
    protos = sorted(
        {
            info.negotiated_protocol_version
            for s in case.servers
            for info in s.debug_info
            if info.negotiated_protocol_version
        }
    )
    table.add_row("Negotiated MCP protocol version(s) (from --debug file)", _cell(", ".join(protos) or "n/a"))
    n = log_counts(case)
    roots = ", ".join(f"{_rel(r.path, case.target_root)} ({r.origin})" for r in case.cache_roots) or "none found"
    table.add_row("MCP log cache folder(s)", _cell(roots))
    table.add_row("MCP log files", str(len(case.mcp_log_files)))
    table.add_row("--debug files", str(len(case.debug_files)))
    table.add_row("Log tool calls", f"{n['log_calls']} (matched {n['log_calls_matched']}, of which by toolUseId "
                  f"{n['log_calls_matched_by_tool_use_id']}; ambiguous {n['log_calls_ambiguous']}; "
                  f"log-only {n['log_calls_log_only']}; from debug file only {n['log_calls_from_debug_only']})")
    table.add_row("Transcript MCP calls without log record", str(n["transcript_mcp_calls_no_log_record"]))
    if case.cross_check:
        cc = case.cross_check
        table.add_row("Debug vs MCP log", f"matched {cc.matched} (identical {cc.identical}, redaction-only "
                      f"{cc.redaction_only}, error-object {cc.error_object}, differs {cc.differs}); "
                      f"MCP-log only {cc.mcp_log_only}; debug only {cc.debug_only}")
    shown_text = "shown (--show-sensitive)"
    if case.filter is not None:
        shown_text += "; values of other sessions stay withheld"
    table.add_row("Sensitive values", shown_text if case.sensitive_values_shown
                  else f"withheld: {n['sensitive_items_withheld']} item(s) (see `mcpeek logs`)")
    console.print(table)
    if case.warnings:
        _say(console, "Warnings:", "yellow")
        for w in case.warnings:
            _say(console, f"  - {w}")


# ---------------------------------------------------------------------------
# logs: per-file details, cross-check, sensitive items
# ---------------------------------------------------------------------------


def _file_matches(path: Optional[str], needle: Optional[str]) -> bool:
    return not needle or (path is not None and needle in path)


def _cross_check_items(cc, file_filter: Optional[str]) -> list:
    """Cross-check items of files that match --file (both sources count)."""
    if not file_filter:
        return list(cc.items)
    return [it for it in cc.items
            if _file_matches(it.mcp_log_source, file_filter) or _file_matches(it.debug_source, file_filter)]


def logs_to_jsonable(case, records: bool, file_filter: Optional[str]) -> dict:
    mcp_files = []
    for f in case.mcp_log_files:
        if not _file_matches(f.path, file_filter):
            continue
        d = f.model_dump(mode="json")  # record_count: number of records
        if records:
            d["records"] = [r.model_dump(mode="json") for r in f.entries]
        mcp_files.append(d)
    dbg_files = []
    for f in case.debug_files:
        if not _file_matches(f.path, file_filter):
            continue
        d = f.model_dump(mode="json")
        if records:
            d["mcp_entries"] = [e.model_dump(mode="json") for e in f.mcp_entries]
        dbg_files.append(d)
    cc = None
    if case.cross_check:
        cc = case.cross_check.model_dump(mode="json")
        if file_filter:
            # the counts cover all files; items and context only the matching ones
            cc["items"] = [i.model_dump(mode="json") for i in _cross_check_items(case.cross_check, file_filter)]
            cc["context"] = [c for c in case.cross_check.context if file_filter in c]
            cc["file_filter"] = file_filter
            cc["counts_scope"] = "all files"
    return {
        "sensitive_values_shown": case.sensitive_values_shown,
        "cache_roots": [r.model_dump(mode="json") for r in case.cache_roots],
        "mcp_log_files": mcp_files,
        "debug_files": dbg_files,
        "debug_latest_links": [x.model_dump(mode="json") for x in case.debug_latest_links],
        "skipped_symlinks": [x.model_dump(mode="json") for x in case.skipped_symlinks],
        "path_aliases": [x.model_dump(mode="json") for x in case.path_aliases],
        "cross_check": cc,
        "sensitive_items": [i.model_dump(mode="json") for i in collect_sensitive(case, file_filter)],
    }


def collect_sensitive(case, file_filter: Optional[str] = None):
    seen = set()
    out = []
    for f in case.mcp_log_files:
        if not _file_matches(f.path, file_filter):
            continue
        for r in f.entries:
            for i in r.sensitive:
                k = (i.source, i.kind, i.field, i.sha256_prefix)
                if k not in seen:
                    seen.add(k)
                    out.append(i)
    for f in case.debug_files:
        if not _file_matches(f.path, file_filter):
            continue
        for e in f.mcp_entries:
            for i in e.sensitive:
                k = (i.source, i.kind, i.field, i.sha256_prefix)
                if k not in seen:
                    seen.add(k)
                    out.append(i)
    return out


# Below this console width the per-file tables of `logs` are printed as one
# field/value table per file, so that timestamps and ids stay whole.
_LOGS_WIDE_MIN = 130


def _cards(console: Console, title: str, cards: list[list[tuple[str, str]]]) -> None:
    t = Table(title=_cell(title), show_header=False, show_lines=False)
    t.add_column("Field", no_wrap=True, style="bold")
    _col(t, "Value")
    for i, card in enumerate(cards):
        if i:
            t.add_section()
        for k, v in card:
            t.add_row(k, _cell(v))
    console.print(t)


def render_logs(console: Console, case, records: bool, file_filter: Optional[str]) -> None:
    root = case.target_root
    wide = console.width >= _LOGS_WIDE_MIN
    t = Table(title="MCP log cache folders")
    _col(t, "Folder")
    _col(t, "Origin")
    _col(t, "Location status")
    _col(t, "Files", justify="right")
    for r in case.cache_roots:
        t.add_row(_cell(_rel(r.path, root)), r.origin, r.status, str(r.log_files))
    console.print(t)

    rows = []
    for f in case.mcp_log_files:
        if not _file_matches(f.path, file_filter):
            continue
        server = f.server if f.name_status == "unique" else f"{f.server_dir} ({f.name_status}: {', '.join(f.name_candidates) or 'no candidates'})"
        if f.possibly_shared:
            server += f" (possibly shared by servers whose names sanitize to {f.server_dir})"
        sess = ", ".join(s[:8] for s in f.session_ids)
        if f.session_switches:
            sess += f" ({len(f.session_switches)} switch(es))"
        notes = list(f.notes)
        if f.invalid_lines:
            notes.append(f"invalid lines: {f.invalid_lines}")
        rows.append([("File", _rel(f.path, root)), ("Server", server),
                     ("Process start (file name)", f.file_name_time or "(non-conforming name)"),
                     ("Records (classified / unclassified)", f"{f.record_count} ({f.classified} / {f.unclassified})"),
                     ("Sessions", sess or "-"), ("Mode (markers)", f.mode),
                     ("Calls / connects", f"{f.tool_calls} / {f.connect_attempts}"),
                     ("Notes", "\n".join(notes) or "-")])
    if not rows and file_filter:
        _say(console, f"Per-server MCP log files: no matching files (--file {file_filter})")
    elif wide:
        t = Table(title="Per-server MCP log files", show_lines=True)
        _col(t, "File", ratio=3)
        _col(t, "Server", ratio=1)
        _ts_column(t, "Process start (file name)")
        _col(t, "Records (classified / unclassified)", ratio=1)
        _col(t, "Sessions", ratio=2)
        _col(t, "Mode (markers)", ratio=1)
        _col(t, "Calls / connects", ratio=1)
        _col(t, "Notes", ratio=3)
        for card in rows:
            t.add_row(*(_cell(v) for _, v in card))
        console.print(t)
    else:
        _cards(console, "Per-server MCP log files", rows)
    if case.filter is not None:
        _say(console, filter_summary(case.filter), "dim")
        for x in case.filter.filtered_out_by_file:
            if _file_matches(x.path, file_filter):
                _say(console, "  " + left_out_text(x, root), "dim")

    if case.debug_files or case.debug_latest_links:
        rows = []
        for f in case.debug_files:
            if not _file_matches(f.path, file_filter):
                continue
            notes = list(f.notes)
            if f.entrypoints:
                notes.append("cc_entrypoint " + ", ".join(f.entrypoints))
            if f.runtime_arms:
                notes.append("mcp runtime arm " + ", ".join(f.runtime_arms))
            if f.prior_unclean_sessions:
                notes.append("prior session exited without cleanup: " + ", ".join(f.prior_unclean_sessions))
            rows.append([("File", _rel(f.path, root)), ("Session (source)", f"{f.session_id or '-'}\n({f.session_id_source})"),
                         ("Entries / continuation / JSON-encoded",
                          f"{f.entry_count} / {f.continuation_lines} / {f.json_encoded_entries}"),
                         ("Levels", ", ".join(f"{k} {v}" for k, v in f.levels.items())),
                         ("MCP mirror lines (servers)", f"{f.mirror_lines} ({', '.join(f.servers)})"),
                         ("Dispatch / denials", f"{f.dispatch_starts} / {f.permission_denials}"),
                         ("Notes", "\n".join(notes) or "-")])
        if not rows and file_filter:
            _say(console, f"--debug files: no matching files (--file {file_filter})")
        elif wide:
            t = Table(title="--debug files", show_lines=True)
            _col(t, "File", ratio=3)
            _id_column(t, "Session (source)", 36)
            _col(t, "Entries / continuation / JSON-encoded", ratio=1)
            _col(t, "Levels", ratio=1)
            _col(t, "MCP mirror lines (servers)", ratio=2)
            _col(t, "Dispatch / denials", ratio=1)
            _col(t, "Notes", ratio=3)
            for card in rows:
                t.add_row(*(_cell(v) for _, v in card))
            console.print(t)
        else:
            _cards(console, "--debug files", rows)
        for ln in case.debug_latest_links:
            if ln.kind == "symlink":
                _say(console, f"latest: symlink -> {ln.target or '?'} (not followed"
                     + (f"; names {_rel(ln.resolves_to, root)}" if ln.resolves_to else "; target not present in this folder")
                     + ")")
            else:
                _say(console, "latest: regular file" + (f", identical to {_rel(ln.identical_to, root)}"
                                                        if ln.identical_to else ", parsed as its own debug file"))
    for sl in case.skipped_symlinks:
        _say(console, f"symlink not followed: {_rel(sl.path, root)} -> {sl.target or '?'} "
                      f"(leads outside the target root; looked up as {sl.looked_up_as})")
    for al in case.path_aliases:
        _say(console, f"read once: {_rel(al.path, root)} is the same {al.looked_up_as} as {_rel(al.same_as, root)}"
                      + (f" (symlink -> {al.target})" if al.target else ""))

    cc = case.cross_check
    if cc is not None:
        console.print(Text.assemble(
            ("Debug file vs MCP log", "bold"),
            (" (counts over all files)" if file_filter else "") + ": ",
            f"{cc.debug_mirror_lines} mirror line(s), {cc.mcp_log_records_in_scope} "
            f"MCP-log record(s) in scope; matched {cc.matched} (identical {cc.identical}, redaction-only "
            f"{cc.redaction_only}, error-object {cc.error_object}, differs from debug copy {cc.differs}); "
            f"MCP-log only {cc.mcp_log_only}; debug only {cc.debug_only}; offsets (MCP log - debug, ms: count) "
            f"{', '.join(f'{k}: {v}' for k, v in cc.offset_histogram_ms.items()) or 'none'}; outside 0-5 ms {cc.offsets_outside_0_5ms}; session mismatches "
            f"{cc.session_mismatches}; order inversions {cc.order_inversions}",
        ))
        for c in cc.context:
            if not file_filter or file_filter in c:
                _say(console, f"  context: {_rel(c, root)}")
        items = _cross_check_items(cc, file_filter)
        if items and not wide:
            cards = []
            for it in items:
                detail = list(it.notes)
                for m in it.masked_in_debug:
                    detail.append(f"masked in debug: {m.kind}" + (f" {m.field}" if m.field else "")
                                  + (f" = {m.value}" if m.value is not None else f" ({m.size_bytes} B, sha256 {m.sha256_prefix})"))
                if it.status in ("debug only", "mcp-log only", "differs from debug copy"):
                    detail.append(_short_text(it.text or it.debug_text))
                cards.append([("Status", it.status), ("Server", it.server), ("Message", it.message_id),
                              ("MCP log", _rel(it.mcp_log_source, root)), ("Debug file", _rel(it.debug_source, root)),
                              ("Offset ms", "-" if it.offset_ms is None else str(it.offset_ms)),
                              ("Detail", "\n".join(detail) or "-")])
            _cards(console, "Cross-check: pairs that are not identical, and one-source records", cards)
        elif items:
            t = Table(title="Cross-check: pairs that are not identical, and one-source records", show_lines=True)
            _col(t, "Status")
            _col(t, "Server")
            _col(t, "Message")
            _col(t, "MCP log")
            _col(t, "Debug file")
            _col(t, "Offset ms", justify="right")
            _col(t, "Detail")
            for it in items:
                detail = list(it.notes)
                for m in it.masked_in_debug:
                    detail.append(f"masked in debug: {m.kind}" + (f" {m.field}" if m.field else "")
                                  + (f" = {m.value}" if m.value is not None else f" ({m.size_bytes} B, sha256 {m.sha256_prefix})"))
                if it.status in ("debug only", "mcp-log only", "differs from debug copy"):
                    detail.append(_short_text(it.text or it.debug_text))
                t.add_row(_cell(it.status), _cell(it.server), _cell(it.message_id), _cell(_rel(it.mcp_log_source, root)),
                          _cell(_rel(it.debug_source, root)), "-" if it.offset_ms is None else str(it.offset_ms),
                          _cell("\n".join(detail)))
            console.print(t)

    items = collect_sensitive(case, file_filter)
    if items:
        t = Table(title="Sensitive values " + ("(shown: --show-sensitive)" if case.sensitive_values_shown
                                                else "(withheld; use --show-sensitive to print them)"))
        _col(t, "Kind")
        _col(t, "Field")
        _col(t, "Size", justify="right")
        _id_column(t, "SHA-256 prefix", 12)
        _col(t, "Source")
        if case.sensitive_values_shown:
            _col(t, "Value")
        for i in items:
            row = [_cell(i.kind), _cell(i.field or "-"), f"{i.size_bytes} B", _cell(i.sha256_prefix),
                   _cell(_rel(i.source, root))]
            if case.sensitive_values_shown:
                row.append(_cell(i.value))
            t.add_row(*row)
        console.print(t)

    if records:
        narrow = console.width < _RECORDS_WIDE_MIN
        for f in case.mcp_log_files:
            if not _file_matches(f.path, file_filter):
                continue
            t = Table(title=_cell(f"Records: {_rel(f.path, root)}"), show_lines=narrow)
            if narrow:
                t.add_column("Line / timestamp / session", no_wrap=True, min_width=24)
                _col(t, "Key, message id: text")
            else:
                _col(t, "Line", justify="right")
                _ts_column(t, "Timestamp")
                _id_column(t, "Session", 8)
                _col(t, "Key")
                _col(t, "Message id")
                _col(t, "Text")
            for r in f.entries:
                text = r.text + (("  [" + "; ".join(r.notes) + "]") if r.notes else "")
                if narrow:
                    t.add_row(_cell(f"line {r.line}\n{r.timestamp or '-'}\n{(r.session_id or '-')[:8]}"),
                              _cell(f"{r.key}, {r.message_id}: {text}"))
                else:
                    t.add_row(str(r.line), _cell(r.timestamp or "-"), _cell((r.session_id or "-")[:8]), _cell(r.key),
                              _cell(r.message_id), _cell(text))
            console.print(t)
        for f in case.debug_files:
            if not _file_matches(f.path, file_filter):
                continue
            t = Table(title=_cell(f"MCP-relevant entries: {_rel(f.path, root)}"), show_lines=narrow)
            if narrow:
                t.add_column("Line / timestamp / level", no_wrap=True, min_width=24)
                _col(t, "Server, message id: text")
            else:
                _col(t, "Line", justify="right")
                _ts_column(t, "Timestamp")
                _col(t, "Level")
                _col(t, "Server")
                _col(t, "Message id")
                _col(t, "Text")
            for e in f.mcp_entries:
                text = e.text + (("  [" + "; ".join(e.notes) + "]") if e.notes else "")
                if narrow:
                    t.add_row(_cell(f"line {e.line}\n{e.timestamp or '-'}\n{e.level or '-'}"),
                              _cell(f"{e.server or '-'}, {e.message_id}: {text}"))
                else:
                    t.add_row(str(e.line), _cell(e.timestamp or "-"), _cell(e.level or "-"), _cell(e.server or "-"),
                              _cell(e.message_id), _cell(text))
            console.print(t)


def _short_text(text: Optional[str], limit: int = 200) -> str:
    if not text:
        return ""
    t = " ".join(text.split())
    return t if len(t) <= limit else t[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# report: a self-contained HTML/Markdown export bundling the views above
# ---------------------------------------------------------------------------


_MD_ACTIVE_RE = re.compile(r"([\\`*_\[\]|~#])")


def _md(text: Any) -> str:
    """Evidence text for the Markdown report: control characters made
    visible, & < > HTML-escaped and Markdown-active characters (including the
    table separator |) backslash-escaped, one line."""
    t = html.escape(visible(str(text)).replace("\r", " ").replace("\n", " "), quote=False)
    return _MD_ACTIVE_RE.sub(r"\\\1", t)


def _ts_order(ts: Optional[str]) -> tuple:
    ms = ts_ms(ts)
    return (0, ms, ts) if ms is not None else (1, 0, ts or "")


def _plain(text: Any) -> str:
    """Evidence text for the HTML report's text block, which is HTML-escaped
    as a whole: control characters made visible, one line, nothing else
    escaped."""
    return visible(str(text)).replace("\n", " ")


def render_report_markdown(case, redact: bool, esc=_md) -> str:
    """The report as Markdown. ``esc`` escapes each evidence value (the HTML
    report passes _plain and escapes the whole text instead)."""
    lines: list[str] = []
    lines.append(f"# MCPeek report: {esc(case.target_root)}\n")
    lines.append("## Scope statement\n")
    lines.append(
        "MCPeek is a read-only, offline reconstruction of MCP activity from "
        "Claude Code CLI on-disk artifacts. It emits no attribution verdict: "
        "it does not classify activity, infer intent or actor, recover tool "
        "descriptions/schemas, read network captures, or verify artifact "
        "integrity. See README for the full scope statement.\n"
    )
    n = log_counts(case)
    lines.append("## Overview\n")
    lines.append(f"- HOME on the examined host: {esc(_home_text(case))}")
    lines.append(f"- Servers: {len(case.servers)}")
    lines.append(f"- Tools observed: {len(case.tools)}")
    lines.append(f"- Sessions: {len(case.sessions)}")
    lines.append(f"- Subagents: {len(case.subagents)}")
    lines.append(f"- Tool calls: {len(case.tool_calls)}")
    lines.append(f"- OAuth clients: {len(case.oauth_clients)}")
    lines.append(f"- Grants: {len(case.grants)}")
    lines.append(f"- MCP log files: {len(case.mcp_log_files)}; --debug files: {len(case.debug_files)}")
    lines.append(f"- Log tool calls: {n['log_calls']} (matched {n['log_calls_matched']}, ambiguous "
                 f"{n['log_calls_ambiguous']}, log-only {n['log_calls_log_only']})")
    lines.append(f"- Transcript MCP calls without log record: {n['transcript_mcp_calls_no_log_record']}")
    lines.append("- Sensitive log values: " + ("shown" if case.sensitive_values_shown
                                              else f"withheld ({n['sensitive_items_withheld']} item(s))") + "\n")
    if case.filter is not None:
        lines.append("## Session filter\n")
        for label, text in filter_lines(case.filter):
            lines.append(f"- {label}: {esc(text)}")
        for x in case.filter.filtered_out_by_file:
            lines.append(f"- {esc(left_out_text(x, case.target_root))}")
        lines.append("- Configured servers, OAuth clients and grants are listed in full; servers not in the current "
                     "configuration come from the log files shown.\n")

    lines.append("## Servers\n")
    oauth = any(s.oauth is not None for s in case.servers)
    lines.append("| Server | Scope | Transport | Command/URL | Env | Headers | " + ("OAuth config | " if oauth else "")
                 + "MCP log |")
    lines.append("|---|---|---|---|---|---|---|" + ("---|" if oauth else ""))
    for s in case.servers:
        cmd_or_url = _command_or_url(s, redact, "; ")
        env = redact_env(s.env, redact)
        env_str = "; ".join(f"{k}={v}" for k, v in env.items()) if env else "-"
        oauth_cell = f"{esc(_oauth_text(s, redact, '; '))} | " if oauth else ""
        lines.append(f"| {esc(s.name)} | {esc(s.scope)} | {esc(_transport_text(s))} | {esc(cmd_or_url)} | {esc(env_str)} | "
                     f"{esc(_headers_text(s, redact, '; '))} | {oauth_cell}{esc(_log_summary_cell(s.log_info))} |")
    lines.append("")

    if case.log_calls:
        lines.append("## MCP log tool calls\n")
        lines.append("| Start | Session | Server | Tool | Outcome | Duration | Join | Source |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for lc in sorted(case.log_calls, key=lambda c: _ts_order(c.start_timestamp)):
            join = lc.join_status + (f" ({lc.join_method})" if lc.join_method else "")
            outcome = lc.outcome + (f" ({_RETRY_NOTE})" if _retried(lc.notes) else "")
            lines.append(f"| {esc(lc.start_timestamp)} | {esc((lc.session_id or '-')[:8])} | {esc(lc.server)} | "
                         f"{esc(lc.tool)} | {esc(outcome)} | {esc(format_duration(lc.duration))} | {esc(join)} | "
                         f"{esc(_rel(lc.source, case.target_root))} |")
        lines.append("")

    lines.append("## OAuth credentials\n")
    lines.append("| Server | Server URL | Client ID kind | Client ID | Issuer |")
    lines.append("|---|---|---|---|---|")
    for c in case.oauth_clients:
        lines.append(f"| {esc(c.server_name)} | {esc(redact_url(c.server_url, redact) or '-')} | "
                     f"{c.client_id_kind.value} | {esc(redact_url(c.client_id, redact) or '-')} | "
                     f"{esc(redact_url(c.issuer, redact) or '-')} |")
    lines.append("")

    lines.append("## Sessions\n")
    lines.append("| Session | cwd | Msgs | Tool calls | MCP calls | Subagents |")
    lines.append("|---|---|---|---|---|---|")
    for s in case.sessions:
        lines.append(
            f"| {esc(s.session_uuid)} | {esc(', '.join(sorted(s.cwds)))} | {s.message_count} | "
            f"{s.tool_call_count} | {s.mcp_tool_call_count} | {s.subagent_count} |"
        )
    lines.append("")

    if case.warnings:
        lines.append("## Warnings\n")
        for w in case.warnings:
            lines.append(f"- {esc(w)}")
        lines.append("")

    return "\n".join(lines)


def _h(text: str) -> str:
    return html.escape(visible(text))


def render_report_html(case, redact: bool) -> str:
    # Minimal, dependency-free rendering: the report text in <pre> plus a real
    # HTML table for the servers view, so the report is usable standalone
    # without a markdown renderer. The text is built from the values as they
    # are (no Markdown escapes) and HTML-escaped once, so evidence shows
    # literally.
    esc = html.escape(render_report_markdown(case, redact, esc=_plain))
    servers_rows = ""
    oauth = any(s.oauth is not None for s in case.servers)
    for s in case.servers:
        cmd_or_url = _command_or_url(s, redact, "; ")
        env = redact_env(s.env, redact)
        env_str = "; ".join(f"{k}={v}" for k, v in env.items()) if env else "-"
        servers_rows += (
            f"<tr><td>{_h(s.name)}</td><td>{_h(s.scope)}</td>"
            f"<td>{_h(_transport_text(s))}</td><td>{_h(cmd_or_url or '-')}</td>"
            f"<td>{_h(env_str)}</td><td>{_h(_headers_text(s, redact, '; '))}</td>"
            + (f"<td>{_h(_oauth_text(s, redact, '; '))}</td>" if oauth else "")
            + f"<td>{_h(_log_summary_cell(s.log_info))}</td></tr>\n"
        )
    oauth_th = "<th>OAuth config</th>" if oauth else ""
    return f"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>MCPeek report: {_h(case.target_root)}</title>
<style>
body {{ font-family: -apple-system, sans-serif; margin: 2rem; }}
table {{ border-collapse: collapse; margin-bottom: 1.5rem; }}
td, th {{ border: 1px solid #ccc; padding: 4px 8px; font-size: 0.85rem; }}
pre {{ background: #f5f5f5; padding: 1rem; white-space: pre-wrap; }}
</style>
</head>
<body>
<h1>MCPeek report</h1>
<h2>Servers</h2>
<table><tr><th>Server</th><th>Scope</th><th>Transport</th><th>Command/URL</th><th>Env</th><th>Headers</th>{oauth_th}<th>MCP log</th></tr>
{servers_rows}</table>
<h2>Full report</h2>
<pre>{esc}</pre>
</body>
</html>
"""
