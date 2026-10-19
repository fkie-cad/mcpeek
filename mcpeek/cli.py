"""MCPeek command-line interface.

Nine subcommands (servers, tools, sessions, timeline, logs, credentials,
grants, info, report), global options -t/--target, --home, --cache-dir,
--debug-file, --session, --project, --json, --redact, --show-sensitive,
`sessions --quick` (a listing from the first and last records of each
transcript, without parsing it), and (on `timeline` only)
the native-tool visibility toggle: default shows MCP calls plus
subagent-spawn rows as first class and native tools as counts only,
--all-tools shows every call tagged, --mcp-only shows strictly mcp__* calls
(including ones made inside a subagent). Spawn/delegation detection is by
id-stitch against subagents/agent-<id>.meta.json's toolUseId field ONLY --
never by matching a tool name -- because in this Claude Code version the
spawn tool is literally named "Agent", not "Task". See parse.py.
"""
from __future__ import annotations

import os
import sys

import click
from rich.console import Console
from rich.text import Text

from . import render
from .loader import SelectionError, SessionSelection, TargetLoader
from .models import Case
from .parse import build_case, session_filter


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "-t",
    "--target",
    "target",
    # Not required=True: a required option on the parent group is checked
    # before Click parses the subcommand's own args, so `mcpeek timeline
    # --help` would fail with "Missing option '-t'". The check is deferred to
    # _load_case(), which every subcommand calls and `--help` never reaches.
    # A given path must exist (usage error, exit 2).
    default=None,
    type=click.Path(exists=True, file_okay=False),
    help="Home-like root containing .claude.json and .claude/ (what ~ was on the examined host). Required.",
)
@click.option(
    "--home",
    "home",
    default=None,
    metavar="PATH",
    help="HOME on the examined host that the target root stands for (e.g. /root or /home/alice). Project paths "
    "recorded in .claude.json and transcripts are mapped below it to find project-scope settings.local.json and "
    ".mcp.json. Default: inferred (see `info`).",
)
@click.option(
    "--cache-dir",
    "cache_dirs",
    multiple=True,
    type=click.Path(file_okay=False),
    help="Additional cache folder holding claude-cli-nodejs/ MCP logs (the XDG_CACHE_HOME value, or the "
    "claude-cli-nodejs folder itself). Repeatable. The default locations under the target "
    "(.cache, Library/Caches, AppData/Local), <target>/claude-cli-nodejs and <target>/*/claude-cli-nodejs are "
    "always searched.",
)
@click.option(
    "--debug-file",
    "debug_files",
    multiple=True,
    type=click.Path(),
    help="Additional --debug file (or folder of them), e.g. a path given to `claude --debug-file` or "
    "CLAUDE_CODE_DEBUG_LOGS_DIR. Repeatable. .claude/debug/ under the target is always read.",
)
@click.option(
    "--session",
    "session_values",
    multiple=True,
    metavar="ID",
    help="Only this session: the session id `sessions --quick` shows, the transcript file name, or a prefix of "
    "either (at least 4 characters) that no other session has. Repeatable. Only the selected transcripts are "
    "parsed, with their sub-agent and spilled-result folders; MCP logs and --debug files are narrowed to the "
    "selected sessions (see README, Selecting sessions). An ambiguous prefix is a usage error that lists the "
    "candidates; one that matches nothing is a usage error that points to `sessions --quick`.",
)
@click.option(
    "--project",
    "project_values",
    multiple=True,
    metavar="P",
    help="Only sessions of this project: the encoded project folder name under .claude/projects, the project path "
    "on the examined host (encoded the way the CLI does: every character other than A-Z, a-z, 0-9 becomes '-'), or "
    "a prefix of the folder name that only one folder has. Repeatable. With --session, the --session values are "
    "matched within these projects. A value that matches no folder or several is a usage error that lists them.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON instead of a table.")
@click.option(
    "--redact",
    is_flag=True,
    help="Mask configuration values: credential-shaped keys (accessToken, refreshToken, idToken, clientSecret, "
    "also snake_case), every MCP server env and header value (names are kept), credential-shaped values in stdio "
    "command lines and headersHelper commands (after a name or flag containing token, key, secret, password, "
    "passwd, auth or credential; after an authorization scheme word such as Bearer, Basic, Digest or token, in "
    "the same argument or as the next one; well-known token formats), and the userinfo, query values and "
    "fragment of every URL value (server URLs, OAuth server URL, issuer, redirect URI). Transcript input/result "
    "summaries are not changed. Values from MCP logs and --debug files stay withheld. Cannot be combined with "
    "--show-sensitive.",
)
@click.option(
    "--show-sensitive",
    "show_sensitive",
    is_flag=True,
    help="Print values from MCP logs and --debug files that can be secrets or personal data (connect-time "
    "stderr, HTTP header values, URL userinfo, query values and fragments, tool error text, error text of "
    "connection and transport errors, the text of records no template matches, elicitation questions, schemas "
    "and answers, proxy settings, permission rules). By default they are withheld and listed by kind, size, "
    "SHA-256 prefix (both over exactly the printed value) and source file:line. Under --session or --project "
    "the values of other sessions' records stay withheld.",
)
@click.version_option(package_name="mcpeek")
@click.pass_context
def main(ctx: click.Context, target: str, home: str | None, cache_dirs: tuple[str, ...],
         debug_files: tuple[str, ...], session_values: tuple[str, ...], project_values: tuple[str, ...],
         as_json: bool, redact: bool, show_sensitive: bool) -> None:
    """MCPeek -- a read-only, offline forensic CLI for reconstructing MCP
    activity from Claude Code CLI on-disk artifacts.

    MCPeek rebuilds the MCP tool-call timeline from transcripts, sub-agent
    sidecars, per-server MCP logs and --debug files, and lists servers,
    tools, grants and spilled results. It emits no attribution verdict: it
    does not classify activity, infer intent or actor, recover tool
    descriptions/schemas, read the wire, or verify artifact integrity.

    \b
    Sensitive values: the MCP log keeps connect-time stderr, header values
    (other than *authorization), URL query values, error text and
    elicitation answers in clear. The --debug file copy masks values that
    follow a keyword (token=, password:, Bearer ...), URL userinfo and
    well-known token formats; other values (a bare secret in stderr, a ?sig=
    query value, a custom header value) stay in clear there. MCPeek
    withholds these values from both logs unless --show-sensitive is given.
    --redact masks configuration values (credential-shaped keys, server env
    and header values, credential-shaped command-line values, URL
    userinfo/query/fragment); it never reveals log values, and combining it
    with --show-sensitive is an error.

    \b
    Selecting sessions: `sessions --quick` lists the transcripts from their
    first and last records without parsing them; --session ID (a prefix of
    at least 4 characters) and --project P then restrict every command to
    those sessions. JSON output then carries a "filter" object; the
    configuration views add "filter_applies" and "filter_note".

    Global options go before the subcommand. Run `mcpeek -t <target> info`
    for a case overview, or see README.md. Exit status: 0 on success, 2 on a
    usage error (unknown option, missing or nonexistent --target, a --session
    or --project value that matches nothing or more than one, ...).
    """
    if redact and show_sensitive:
        raise click.UsageError("--redact and --show-sensitive are mutually exclusive")
    _tolerant_streams()
    if home is not None and not (home.startswith("/") or (len(home) > 2 and home[1] == ":" and home[2] in "\\/")):
        raise click.BadParameter("must be an absolute path on the examined host", param_hint="'--home'")
    ctx.ensure_object(dict)
    ctx.obj["target"] = target
    ctx.obj["home"] = home
    ctx.obj["cache_dirs"] = cache_dirs
    ctx.obj["debug_files"] = debug_files
    ctx.obj["selection"] = SessionSelection(tuple(session_values), tuple(project_values))
    ctx.obj["json"] = as_json
    ctx.obj["redact"] = redact
    ctx.obj["show_sensitive"] = show_sensitive
    # Human-readable table output goes to stdout via this console. Kept
    # separate from the stderr console so that --json output is never
    # interleaved with diagnostic warnings on stdout. Piped to a file, tables
    # use COLUMNS or a wide default, so timestamps and ids are not cut.
    ctx.obj["console"] = _stdout_console()
    ctx.obj["stderr_console"] = Console(stderr=True)


def _tolerant_streams() -> None:
    """Text from evidence can hold lone surrogates (JSON "\\ud800" escapes);
    print them as backslash escapes instead of failing."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass


def _stdout_console() -> Console:
    if sys.stdout.isatty():
        return Console()
    cols = os.environ.get("COLUMNS", "")
    return Console(width=int(cols) if cols.isdigit() and int(cols) > 0 else 240)


def _loader(ctx: click.Context) -> TargetLoader:
    if not ctx.obj.get("target"):
        raise click.UsageError("Missing option '-t' / '--target'.")
    return TargetLoader(ctx.obj["target"], cache_dirs=ctx.obj.get("cache_dirs", ()),
                        debug_files=ctx.obj.get("debug_files", ()), home=ctx.obj.get("home"),
                        selection=ctx.obj.get("selection"))


def _load_case(ctx: click.Context) -> Case:
    loader = _loader(ctx)
    try:
        discovered = loader.discover()
    except SelectionError as exc:
        raise click.UsageError(str(exc)) from None
    case = build_case(discovered, show_sensitive=ctx.obj.get("show_sensitive", False))
    if (not discovered.user_config_path and not discovered.sessions and not discovered.mcp_log_paths
            and not discovered.debug_files):
        # stderr, not the stdout console (see main()): --json output must
        # stay pure JSON on stdout even when this warning fires.
        ctx.obj["stderr_console"].print(Text.assemble(
            ("warning:", "yellow"),
            f" no .claude.json and no sessions found under {ctx.obj['target']!r} -- is this really a --target root?",
        ))
    return case


@main.command(short_help="Configured MCP servers by scope, with log details.")
@click.pass_context
def servers(ctx: click.Context) -> None:
    """List configured MCP servers (command/args/env or url, headers and the
    configured oauth object), by scope.

    A remote server URL recorded in the MCP log is listed as "(from MCP log)"
    when it is not the configured URL (query values withheld unless
    --show-sensitive). Under --session/--project the configured servers are
    listed in full; the servers not in the current configuration and the MCP
    log details come from the log files shown for the selected sessions, and
    each server shows its calls in the selected sessions and the connection
    attempts in those log files."""
    case = _load_case(ctx)
    if ctx.obj["json"]:
        data = render.servers_to_jsonable(case.servers, ctx.obj["redact"], case)
        render.print_json_raw(render.with_filter(case.filter, "servers", data))
    else:
        render.render_servers(ctx.obj["console"], case.servers, ctx.obj["redact"], case)


@main.command(short_help="MCP tools observed being called, with call counts.")
@click.pass_context
def tools(ctx: click.Context) -> None:
    """List MCP tools observed being called, with transcript and MCP-log call counts."""
    case = _load_case(ctx)
    if ctx.obj["json"]:
        _print_list(ctx, case, "tools", case.tools)
    else:
        render.render_tools(ctx.obj["console"], case.tools)
        _filter_foot(ctx, case)


def _print_list(ctx: click.Context, case: Case, key: str, items: list) -> None:
    """A list output; under a session filter wrapped with the filter object."""
    if case.filter is None:
        render.print_json(items, redact=ctx.obj["redact"])
    else:
        render.print_json_raw(render.with_filter(case.filter, key, render.model_to_jsonable(items)),
                              redact=ctx.obj["redact"])


def _filter_foot(ctx: click.Context, case: Case, note: str | None = None) -> None:
    if case.filter is not None:
        ctx.obj["console"].print(Text(render.visible(render.filter_summary(case.filter)), style="dim"))
        if note:
            ctx.obj["console"].print(Text("session filter: " + note, style="dim"))


@main.command(short_help="Session transcripts with basic stats (--quick: without parsing them).")
@click.option(
    "--quick",
    is_flag=True,
    help="List every top-level transcript without parsing it: session id, cwd and first timestamp from its first "
    "records, last timestamp from its last records (read from the end of the file), file size and mtime, and the "
    "number of sub-agent sidecars and spilled results (names in its companion folder). At most 8 MiB are read from "
    "each end and lines over 1 MiB are skipped, so cwd, first or last can be '-'. Newest last activity first. Reads "
    "no MCP log or --debug file.",
)
@click.option("--limit", type=click.IntRange(min=1), default=None, metavar="N",
              help="With --quick: only the N sessions with the most recent activity (default: all).")
@click.pass_context
def sessions(ctx: click.Context, quick: bool, limit: int | None) -> None:
    """List session transcripts with basic stats.

    \b
    --quick is meant for large homes: it lists the sessions in seconds
    without parsing any transcript; pick one and pass its id (or a prefix)
    with --session to the other commands. The session id is the sessionId
    of the first records (the file name when they give none; a file name
    that differs is shown, and --session matches it too). First and last
    are the first and last records with a timestamp; without --quick they
    are the earliest and latest user or assistant record."""
    if limit is not None and not quick:
        raise click.UsageError("--limit applies to --quick only")
    if quick:
        _quick_sessions(ctx, limit)
        return
    case = _load_case(ctx)
    if ctx.obj["json"]:
        _print_list(ctx, case, "sessions", case.sessions)
    else:
        render.render_sessions(ctx.obj["console"], case.sessions)
        _filter_foot(ctx, case)


def _quick_sessions(ctx: click.Context, limit: int | None) -> None:
    try:
        rows, flt, warnings = _loader(ctx).quick_sessions()
    except SelectionError as exc:
        raise click.UsageError(str(exc)) from None
    total = len(rows)
    if limit is not None:
        rows = rows[:limit]
    case_filter = session_filter(flt, quick=True) if flt is not None else None
    if ctx.obj["json"]:
        render.print_json_raw(render.with_filter(case_filter, "sessions", rows), redact=ctx.obj["redact"])
    else:
        render.render_quick_sessions(ctx.obj["console"], rows, total, case_filter)
    for w in warnings:
        ctx.obj["stderr_console"].print(Text.assemble(("warning:", "yellow"), " " + render.visible(w)))


@main.command(short_help="Tool-call timeline across all sessions, in time order.")
@click.option("--all-tools", "all_tools", is_flag=True, help="Show every tool call, native tools tagged.")
@click.option(
    "--mcp-only",
    "mcp_only",
    is_flag=True,
    help="Show strictly mcp__* calls (transcript and log-only), including ones made inside a delegated subagent; "
    "no server events.",
)
@click.option("--no-server-events", "no_events", is_flag=True,
              help="Hide server lifecycle rows (connect, shutdown, elicitation, ...) from MCP logs and debug files.")
@click.pass_context
def timeline(ctx: click.Context, all_tools: bool, mcp_only: bool, no_events: bool) -> None:
    """Reconstructed tool-call timeline, id-stitched across main + subagent
    transcripts, with subagent nesting depth and denial rows.

    \b
    MCP calls are annotated from the per-server MCP log (and --debug file):
    outcome, logged duration with its precision, offsets, and how the log
    call was joined ("toolUseId" from a debug file, else session, server,
    tool and time). Rows of kind "log-only" are log calls with no transcript
    call, "log-ambiguous" are log calls that fit more than one transcript
    call, "server-event" rows are lifecycle records; every row names its
    source file. A transcript call without log record shows "no log record".
    Rows are in timestamp order across all sessions (ties: session, then
    original order); the Session and Depth columns show the grouping. Log
    rows have no depth: the MCP log cannot tell delegated from direct calls.
    """
    if all_tools and mcp_only:
        raise click.UsageError("--all-tools and --mcp-only are mutually exclusive")
    mode = "all" if all_tools else ("mcp-only" if mcp_only else "default")
    case = _load_case(ctx)
    if ctx.obj["json"]:
        rows = render.timeline_rows(case, mode, server_events=not no_events)
        _print_list(ctx, case, "rows", rows)
    else:
        render.render_timeline(ctx.obj["console"], case, mode, server_events=not no_events)
        _filter_foot(ctx, case)


@main.command(short_help="MCP logs and --debug files, cross-check, withheld values.")
@click.option("--records", is_flag=True, help="Also list every record (MCP logs) and MCP-relevant entry (debug files).")
@click.option("--file", "file_filter", default=None, help="Only files whose path contains this text.")
@click.pass_context
def logs(ctx: click.Context, records: bool, file_filter: str | None) -> None:
    """Per-server MCP logs and --debug files: per-file details, the debug
    vs MCP-log cross-check, and the withheld sensitive values.

    \b
    Per-server MCP log: <cache>/claude-cli-nodejs/<enc(cwd)>/mcp-logs-<server>/<start>.jsonl
    (Linux ~/.cache or $XDG_CACHE_HOME, macOS ~/Library/Caches, Windows
    %LOCALAPPDATA%/claude-cli-nodejs/Cache). --debug file: .claude/debug/<sessionId>.txt.
    Cross-check statuses: identical, redaction-only, error-object, differs
    from debug copy, MCP-log only, debug only. See docs/log-formats.md.
    """
    case = _load_case(ctx)
    if ctx.obj["json"]:
        data = render.logs_to_jsonable(case, records, file_filter)
        if case.filter is not None:
            data = {"filter": case.filter.model_dump(mode="json"), **data}
        render.print_json_raw(data, redact=ctx.obj["redact"])
    else:
        render.render_logs(ctx.obj["console"], case, records, file_filter)


@main.command(short_help="MCP OAuth client registrations (no token values).")
@click.pass_context
def credentials(ctx: click.Context) -> None:
    """List MCP OAuth client registrations (client id kind DCR or CIMD); token values are never shown."""
    case = _load_case(ctx)
    if ctx.obj["json"]:
        _print_list(ctx, case, "oauth_clients", case.oauth_clients)
    else:
        render.render_credentials(ctx.obj["console"], case.oauth_clients, ctx.obj["redact"])
        _filter_foot(ctx, case, render.FILTER_NOTES["oauth_clients"][1])


@main.command(short_help="Permission grants and project .mcp.json approvals.")
@click.pass_context
def grants(ctx: click.Context) -> None:
    """List permission grants (permissions.allow of user- and project-scope
    settings.local.json) and project .mcp.json server approvals
    (enabledMcpjsonServers, disabledMcpjsonServers, enableAllProjectMcpServers
    in those files and in .claude.json project entries), with scope and source.
    A rule with a wildcard in the server position (mcp__*) is listed as
    written with a note, not as a grant for every server."""
    case = _load_case(ctx)
    if ctx.obj["json"]:
        _print_list(ctx, case, "grants", case.grants)
    else:
        render.render_grants(ctx.obj["console"], case.grants, case.target_root)
        _filter_foot(ctx, case, render.FILTER_NOTES["grants"][1])


@main.command(short_help="Case overview: HOME used, counts, warnings.")
@click.pass_context
def info(ctx: click.Context) -> None:
    """Case overview: HOME used, counts, protocol versions, MCP log and debug summary, warnings.

    Under --session/--project also the filter: the sessions selected, of how
    many transcript files (counted by name), the MCP log and --debug files
    kept, and the log calls and events of other sessions left out."""
    case = _load_case(ctx)
    if ctx.obj["json"]:
        data = render.model_to_jsonable(case)
        if case.filter is not None:
            data["filter"] = case.filter.model_dump(mode="json")
        render.print_json_raw(data, redact=ctx.obj["redact"])
    else:
        render.render_info(ctx.obj["console"], case)


@main.command(short_help="Overview, servers, MCP log calls, OAuth clients, sessions, warnings as HTML or Markdown.")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["html", "md"]),
    default="html",
    show_default=True,
    help="Report format.",
)
@click.option(
    "-o",
    "--output",
    "output",
    type=click.Path(dir_okay=False),
    help="Write report to this file instead of stdout. Its folder must exist. A path inside the target root, "
    "inside a --cache-dir folder, or inside or at a --debug-file path is refused (they are evidence).",
)
@click.pass_context
def report(ctx: click.Context, fmt: str, output: str | None) -> None:
    """Export one report (overview, servers, MCP log calls, OAuth clients, sessions, warnings) as HTML or Markdown.

    With -o the report is written to that file. MCPeek does not write into
    the evidence: an output path that resolves (symlinks followed) inside the
    target root, inside a --cache-dir folder, or inside or at a --debug-file
    path is refused with a usage error (exit 2), and nothing is written."""
    if ctx.obj["json"]:
        # The global --json flag has no meaning for `report` (its output is
        # always HTML or Markdown, chosen via --format).
        raise click.UsageError(
            "--json has no effect on `report` (its output is HTML/Markdown, chosen via --format). "
            "Use `mcpeek --json info` (or another subcommand) for machine-readable case data."
        )
    if output:
        _check_output_outside_evidence(ctx, output)
    case = _load_case(ctx)
    redact = ctx.obj["redact"]
    text = render.render_report_html(case, redact) if fmt == "html" else render.render_report_markdown(case, redact)
    if output:
        try:
            with open(output, "w", encoding="utf-8", errors="backslashreplace") as f:
                f.write(text)
        except OSError as exc:
            raise click.BadParameter(f"cannot write the report to {output!r}: {exc.strerror or exc}",
                                     param_hint="'-o' / '--output'") from None
        ctx.obj["console"].print(Text(f"wrote {fmt} report to {output}"))
    else:
        sys.stdout.write(text)


def _check_output_outside_evidence(ctx: click.Context, output: str) -> None:
    """Refuse a report path that resolves inside the target root, a
    --cache-dir folder or a --debug-file folder (or is a --debug-file)."""
    out = os.path.realpath(output)
    roots = [("the target root", ctx.obj.get("target"))]
    roots += [("--cache-dir", c) for c in ctx.obj.get("cache_dirs", ())]
    roots += [("--debug-file", d) for d in ctx.obj.get("debug_files", ())]
    for what, root in roots:
        if not root:
            continue
        r = os.path.realpath(root)
        if out == r or out.startswith(r.rstrip(os.sep) + os.sep):
            raise click.BadParameter(
                f"{output!r} is inside {what} {root!r}; MCPeek does not write into the evidence, "
                "choose an output path outside it",
                param_hint="'-o' / '--output'",
            )


if __name__ == "__main__":
    main()
