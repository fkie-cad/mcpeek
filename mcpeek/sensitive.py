"""Handling of sensitive values found in the MCP log and the --debug file.

Both logs keep values in clear that can be secrets or personal data:
connect-time stderr of stdio servers, HTTP/WebSocket header values (after
${ENV} expansion), URL query parameters and userinfo, tool error text,
error text of connection and transport errors, elicitation questions,
schemas and answers, proxy settings, and any text the catalog does not
know. The --debug copy is redacted by the CLI only where a keyword precedes
the value, so the same handling applies to it.

By default MCPeek withholds these values: the output shows a placeholder
``[withheld:<kind>:<size>B]`` and a SensitiveItem (kind, field, size,
SHA-256 prefix, source file:line). The values are printed only when the
examiner opts in with --show-sensitive.

What is withheld: the free text of every record the catalog does not
classify (unclassified-text), the free-text part of error messages
(error-text: the message of a template that has one, the whole text of an
error-level record whose template is not marked as fixed text), and the
template-specific values below. Template-classified fields that are not
free text (durations, counts, codes, transport, tool names) stay visible.

The size and the SHA-256 prefix are computed over exactly the UTF-8 bytes
of the value that --show-sensitive prints, so an examiner can see that two
places hold the same value without printing it. The --debug copy of a
message is trimmed by the CLI, so a value at the end of a message (stderr
with a trailing newline) can differ there by that whitespace. Short or
guessable values can be recovered from a hash by trying candidates, so
treat the prefix as sensitive when sharing a report.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Optional

from .logcatalog import REDACTED_MARK, Classification
from .models import SensitiveItem

PLACEHOLDER = "[withheld:{kind}:{size}B]"
_HASH_CHARS = 12


@dataclass
class SensitivePolicy:
    show: bool = False


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    kind: str
    field: Optional[str] = None
    json_escaped: bool = False  # value is the inside of a JSON string literal


def decode_json_fragment(raw: str) -> str:
    try:
        return json.loads('"' + raw + '"')
    except (json.JSONDecodeError, ValueError):
        return raw


def make_item(kind: str, value: str, source: str, policy: SensitivePolicy, field: Optional[str] = None) -> SensitiveItem:
    """Size and hash prefix cover exactly the bytes of ``value``, the text
    that --show-sensitive prints (a lone surrogate counts as "?")."""
    data = value.encode("utf-8", errors="replace")
    return SensitiveItem(
        kind=kind,
        field=field,
        size_bytes=len(data),
        sha256_prefix=hashlib.sha256(data).hexdigest()[:_HASH_CHARS],
        source=source,
        value=value if policy.show else None,
    )


def placeholder(item: SensitiveItem) -> str:
    return PLACEHOLDER.format(kind=item.kind, size=item.size_bytes)


def withhold_text(kind: str, value: Optional[str], source: str, policy: SensitivePolicy,
                  field: Optional[str] = None) -> tuple[Optional[str], list[SensitiveItem]]:
    """Withhold a whole free-text value. Returns (display text, items)."""
    if value is None or value.strip() == "":
        return value, []
    item = make_item(kind, value, source, policy, field)
    return (value if policy.show else placeholder(item)), [item]


# Keys of .credentials.json discoveryState whose values are never output,
# whatever the options: every key whose name (case and "_"/"-" ignored)
# contains one of these words (accessToken, refresh_token, tokens,
# clientSecret, codeVerifier, apiKey, privateKey, client_assertion,
# Authorization, cookie, sessionId, password, ...).
CREDENTIAL_WORDS = ("key", "auth", "credential", "assertion", "cookie", "session", "private", "bearer",
                    "password", "passwd", "secret", "token", "verifier")
# Such a key that names metadata rather than a credential (token_endpoint,
# authorization_servers, authorizationServerMetadata, jwks_uri,
# token_endpoint_auth_methods_supported, ...) is walked into instead. Every
# URL in discoveryState keeps scheme, host and path only.
METADATA_SUFFIXES = ("endpoint", "uri", "url", "urls", "supported", "metadata", "servers")
REDACTED_VALUE = "[REDACTED]"
_URL_ONLY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://\S+$")
_URL_START_RE = re.compile(r"^\s*[A-Za-z][A-Za-z0-9+.\-]*://")


def _norm_key(k: str) -> str:
    return re.sub(r"[^a-z0-9]", "", k.lower())


def mask_url(url: str) -> str:
    """URL with userinfo, query values and fragment replaced by "[REDACTED]".
    The whole string is the URL (see url_spans)."""
    out, pos = [], 0
    for sp in sorted(url_spans(url), key=lambda x: x.start):
        out.append(url[pos:sp.start])
        out.append(REDACTED_VALUE)
        pos = sp.end
    out.append(url[pos:])
    return "".join(out)


def scrub_credentials(obj):
    """Copy of a discoveryState value. Every URL keeps scheme, host and path;
    its userinfo, query values and fragment are replaced by "[REDACTED]". The
    value of a credential-shaped key (see CREDENTIAL_WORDS) is replaced by
    "[REDACTED]" unless it is null, a boolean, a URL or a list of URLs; such a
    key with a metadata suffix (see METADATA_SUFFIXES) is walked into like any
    other key."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            nk = _norm_key(k) if isinstance(k, str) else ""
            if not any(w in nk for w in CREDENTIAL_WORDS) or nk.endswith(METADATA_SUFFIXES):
                out[k] = scrub_credentials(v)
            elif v is None or isinstance(v, bool):
                out[k] = v
            elif isinstance(v, str) and _URL_ONLY_RE.match(v):
                out[k] = mask_url(v)
            elif isinstance(v, list) and v and all(isinstance(x, str) and _URL_ONLY_RE.match(x) for x in v):
                out[k] = [mask_url(x) for x in v]
            else:
                out[k] = REDACTED_VALUE
        return out
    if isinstance(obj, list):
        return [scrub_credentials(v) for v in obj]
    if isinstance(obj, str) and _URL_START_RE.match(obj):
        return mask_url(obj)
    return obj


# ---------------------------------------------------------------------------
# Span finders
# ---------------------------------------------------------------------------

_SCHEME_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9+.\-]*://")
_URL_TRAILING = ".,;:)]}"
# a URL right after one of these ends at the matching closer (see url_spans)
_URL_CLOSERS = {"'": "'", "`": "`", "<": ">"}
_CLOSER_RE = {c: re.compile("[" + re.escape(c) + r"\r\n]") for c in _URL_CLOSERS.values()}
_CLOSER_FOLLOW = " \t.,;:)]}>\"'`"
_QUOTE_OR_EOL_RE = re.compile(r'["\r\n]')
# in free text, the query or fragment of a URL runs to the end of the line,
# except before a command-line option or another URL
_FREE_STOP_RE = re.compile(r"[\r\n]|\s+(?=--[A-Za-z]|[A-Za-z][A-Za-z0-9+.\-]*://)")
_WS_RE = re.compile(r"\s")


def _cli_redacted(value: str) -> bool:
    """True for a value the CLI (or its debug redactor) already replaced by
    "[REDACTED]": nothing but the mark and punctuation the redactor left
    (``[REDACTED],`` when it swallowed a closing quote)."""
    return REDACTED_MARK in value and not re.search(r"\w", value.replace(REDACTED_MARK, ""))


def _backslashes_before(text: str, i: int) -> int:
    k = 0
    while i - k > 0 and text[i - k - 1] == "\\":
        k += 1
    return k


def _json_string_end(text: str, start: int, escaped: bool) -> Optional[int]:
    """End of a URL that starts right after the opening quote of a JSON string:
    the closing quote (an unescaped ``"``; in JSON-escaped text, where the
    string opened with ``\\"``, the next ``\\"``). None if the line ends first."""
    pos = start
    while True:
        m = _QUOTE_OR_EOL_RE.search(text, pos)
        if not m or m.group() != '"':
            return None
        i = m.start()
        k = _backslashes_before(text, i)
        if not escaped:
            if k % 2 == 0:
                return i
        elif k % 4 == 1:
            return i - 1
        elif k % 2 == 0:
            return i
        pos = i + 1


def _closed_end(text: str, start: int, closer: str) -> Optional[int]:
    """End of a URL that starts right after ', ` or <: the next closer that
    is followed by the end of the text, whitespace or punctuation. None if the
    line ends first."""
    rx = _CLOSER_RE[closer]
    pos = start
    while True:
        m = rx.search(text, pos)
        if not m or m.group() != closer:
            return None
        i = m.start()
        if i + 1 == len(text) or text[i + 1] in _CLOSER_FOLLOW:
            return i
        pos = i + 1


def _free_end(text: str, start: int) -> int:
    """End of a URL in free text (see url_spans)."""
    m = _WS_RE.search(text, start)
    end = m.start() if m else len(text)
    if "?" in text[start:end] or "#" in text[start:end]:
        m = _FREE_STOP_RE.search(text, start)
        end = m.start() if m else len(text)
        end = start + len(text[start:end].rstrip())
    while end > start and text[end - 1] in _URL_TRAILING:
        seg = text[start:end]
        if seg.endswith(REDACTED_MARK):
            break
        if seg[-1] == ")" and seg.count("(") >= seg.count(")"):
            break
        if seg[-1] == "]" and seg.count("[") >= seg.count("]"):
            break
        end -= 1
    return end


def _url_end(text: str, url_start: int, start: int) -> int:
    """End of the URL whose scheme starts at url_start (``start`` is just past
    its "://")."""
    if not text[:url_start].strip():
        return len(text)
    opener = text[url_start - 1]
    end = None
    if opener == '"':
        end = _json_string_end(text, start, _backslashes_before(text, url_start - 1) % 2 == 1)
    elif opener in _URL_CLOSERS:
        end = _closed_end(text, start, _URL_CLOSERS[opener])
    return _free_end(text, start) if end is None else end


def _url_parts(text: str, start: int, end: int) -> list[Span]:
    """Userinfo, query values and fragment of the URL text[start:end] (the
    part after "://")."""
    spans: list[Span] = []
    rest = text[start:end]
    # userinfo: before the last "@" that precedes the first "/", "?" or "#"
    auth_end = len(rest)
    for sep in "/?#":
        i = rest.find(sep)
        if i != -1:
            auth_end = min(auth_end, i)
    at = rest.rfind("@", 0, auth_end)
    if at > 0 and not _cli_redacted(rest[:at]):
        spans.append(Span(start, start + at, "url-userinfo"))
    q = rest.find("?")
    h = rest.find("#")
    if q != -1 and (h == -1 or q < h):
        # a query value runs to the next "&", to "#" or to the end of the URL
        q_end = h if h != -1 else len(rest)
        pos = q + 1
        for part in rest[q + 1:q_end].split("&"):
            if part:
                if "=" in part:
                    k, v = part.split("=", 1)
                    v_start = pos + len(k) + 1
                    if v and not _cli_redacted(v):
                        spans.append(Span(start + v_start, start + v_start + len(v), "url-query", k))
                elif not _cli_redacted(part):
                    spans.append(Span(start + pos, start + pos + len(part), "url-query"))
            pos += len(part) + 1
    if h != -1 and h + 1 < len(rest) and not _cli_redacted(rest[h + 1:]):
        spans.append(Span(start + h + 1, start + len(rest), "url-fragment"))
    return spans


def url_spans(text: str) -> list[Span]:
    """Userinfo, query values and fragments of every URL in text.

    Where a URL ends: a text that starts with a URL (a configured ``url``, an
    OAuth ``serverUrl``) is one URL to its end. A URL right after an opening
    quote ends at the closing quote: in JSON text the next unescaped ``"``, in
    JSON-escaped text (opened by ``\\"``) the next ``\\"``, after ', ` or < the
    next ', ` or > that is followed by whitespace, punctuation or the end.
    Any other URL in free text ends at whitespace before its query or fragment
    starts; once in the query or fragment it runs to the end of the line
    (whitespace ends it only before a command-line option or another URL).
    Trailing punctuation of such a URL is not part of it. Inside the URL a
    query value runs to the next "&", to "#" or to the end of the URL, a
    fragment to the end of the URL, so quotes, "<", ">" and spaces in them are
    withheld with the value. Values the CLI already replaced by "[REDACTED]"
    are left as they are."""
    spans: list[Span] = []
    pos = 0
    while True:
        m = _SCHEME_RE.search(text, pos)
        if not m:
            return spans
        start = m.end()
        end = _url_end(text, m.start(), start)
        pos = max(start, end)
        spans.extend(_url_parts(text, start, end))


_JSON_STRING_BODY = r'((?:[^"\\]|\\.)*)'


def _object_bounds(text: str, open_idx: int) -> int:
    """Index just past the '}' that closes the '{' at open_idx (string-aware);
    len(text) if unbalanced."""
    depth = 0
    in_str = False
    esc = False
    for i in range(open_idx, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return len(text)


_PAIR_RE = re.compile(r'"((?:[^"\\]|\\.)*)"\s*:\s*"' + _JSON_STRING_BODY + '"')
_MEMBER_RE = re.compile(r'\s*"((?:[^"\\]|\\.)*)"\s*:\s*"' + _JSON_STRING_BODY + r'"\s*([,}])')
_HEADERS_KEEP = {"user-agent", "accept-encoding"}


def _string_members(text: str, open_idx: int, close_idx: int) -> Optional[list[re.Match]]:
    """The members of the JSON object text[open_idx:close_idx], one match per
    member (name group 1, value group 2), or None unless it parses as JSON
    and every value is a string."""
    try:
        obj = json.loads(text[open_idx:close_idx])
    except (ValueError, RecursionError):
        return None
    if not isinstance(obj, dict):
        return None
    if not obj:
        return []
    members = []
    pos = open_idx + 1
    while True:
        m = _MEMBER_RE.match(text, pos, close_idx)
        if not m:
            return None
        members.append(m)
        if m.group(3) == "}":
            return members if m.end() == close_idx else None
        pos = m.end()


def header_spans(text: str, object_key: str = "headers") -> list[Span]:
    """Header values of the JSON object ``object_key`` in text, one span per
    value (User-Agent, Accept-Encoding and values the CLI replaced by
    "[REDACTED]" stay visible). Any whitespace may surround the key, the colon
    and the members. An object that does not parse as JSON with string values
    only (the debug redactor can swallow a closing quote), or a value that is
    neither an object nor null, is withheld as one http-header item from its
    start to its end (to the end of the text if unbalanced): a header value is
    never printed because the object could not be read."""
    spans: list[Span] = []
    done = 0
    for k in re.finditer('"' + re.escape(object_key) + r'"\s*:\s*', text):
        v = k.end()
        if k.start() < done or v >= len(text) or text.startswith("null", v):
            continue
        if text[v] != "{":
            spans.append(Span(v, len(text), "http-header"))
            break
        done = _object_bounds(text, v)
        members = _string_members(text, v, done)
        if members is None:
            spans.append(Span(v, done, "http-header"))
            continue
        for m in members:
            name = decode_json_fragment(m.group(1))
            value = decode_json_fragment(m.group(2))
            if name.lower() in _HEADERS_KEEP or not value or _cli_redacted(value):
                continue
            spans.append(Span(m.start(2), m.end(2), "http-header", name, json_escaped=True))
    return spans


_OPTIONS_URL_RE = re.compile(r'"url"\s*:\s*"')
# where the url value of a transport-options message ends when the JSON does
# not parse: before the last "headers" member, else before the last other member
_OPTIONS_NEXT_RES = (re.compile(r',\s*"headers"\s*:'),
                     re.compile(r',\s*"(?:hasAuthProvider|hasSessionAuth|timeoutMs)"\s*:'))


def unparsed_options_url_spans(text: str) -> list[Span]:
    """In a transport-options message whose JSON does not parse (a raw quote
    in the URL, or a closing quote the debug redactor swallowed), the url value
    from its userinfo, query value, fragment or first raw quote, whichever
    comes first, to the end of the value, as one item. The value ends before the last
    ``"headers"`` member (else before the last other member, else at the end
    of the text), so a quote inside it cannot end it early. Nothing when the
    JSON parses (each part is then its own item, see url_spans) or the URL has
    no such part."""
    i = text.find("{")
    if i == -1:
        return []
    try:
        json.loads(text[i:])
        return []
    except (ValueError, RecursionError):
        pass
    m = _OPTIONS_URL_RE.search(text, i)
    if not m:
        return []
    v = m.end()
    end = len(text)
    for rx in _OPTIONS_NEXT_RES:
        last = None
        for last in rx.finditer(text, v):
            pass
        if last is not None:
            end = last.start()
            if end > v and text[end - 1] == '"':
                end -= 1  # the closing quote (kept unless the redactor swallowed it)
            break
    scheme = _SCHEME_RE.match(text, v)
    parts = _url_parts(text, scheme.end() if scheme else v, end)
    # a raw quote inside the value: what follows it cannot be told apart from
    # the URL, so it is withheld from that quote on as well
    quote = text.find('"', v, end)
    if quote != -1 and (not parts or quote < parts[0].start):
        return [Span(quote, end, "url-unparsed")]
    if not parts:
        return []
    return [Span(parts[0].start, end, parts[0].kind)]


_ENV_SENSITIVE = {"HTTP_PROXY": "proxy-setting", "HTTPS_PROXY": "proxy-setting", "NO_PROXY": "proxy-setting",
                  "NODE_OPTIONS": "node-options"}
_ENV_DEFAULTS = {"not set", "default", ""}


def env_spans(text: str) -> list[Span]:
    spans = []
    for m in _PAIR_RE.finditer(text):
        name = m.group(1)
        kind = _ENV_SENSITIVE.get(name.upper())
        if kind and m.group(2) not in _ENV_DEFAULTS and not m.group(2).startswith(REDACTED_MARK):
            spans.append(Span(m.start(2), m.end(2), kind, name, json_escaped=True))
    return spans


def json_string_span(text: str, key: str, kind: str) -> list[Span]:
    m = re.search('"' + re.escape(key) + r'"\s*:\s*"' + _JSON_STRING_BODY + '"', text)
    if not m or not m.group(1):
        return []
    return [Span(m.start(1), m.end(1), kind, key, json_escaped=True)]


def json_object_span(text: str, key: str, kind: str, field_of: Optional[str] = None,
                     names: bool = True) -> list[Span]:
    """The JSON object value of ``key`` in text. The item's field names the
    object's keys (or the keys of its ``field_of`` member); with
    ``names=False`` it has no field (the key names are withheld too)."""
    m = re.search('"' + re.escape(key) + r'"\s*:\s*\{', text)
    if not m:
        return []
    open_idx = m.end() - 1
    close_idx = _object_bounds(text, open_idx)
    inner = text[open_idx:close_idx]
    try:
        obj = json.loads(inner)
        if isinstance(obj, dict) and field_of is not None:
            obj = obj.get(field_of)
        field = ",".join(obj.keys()) if isinstance(obj, dict) else None
    except (ValueError, RecursionError):
        field = None
    if inner.strip() in ("{}", ""):
        return []
    return [Span(open_idx, close_idx, kind, field if names else None)]


def spans_for_message(mask: Optional[str], message: str, cls: Optional[Classification],
                      message_id: Optional[str] = None, key: Optional[str] = None) -> list[Span]:
    """Sensitive spans of an MCP-log message (or mirror text, or MCP-relevant
    debug-file line) by mask kind. ``cls`` is None for a message the catalog
    does not classify; ``key`` is the record key ("error" for an error-level
    record)."""
    spans: list[Span] = []

    def grp(name: str, kind: str, field: Optional[str] = None) -> None:
        if cls is None:
            return
        sp = cls.span(name)
        if sp and sp[1] > sp[0] and message[sp[0]:sp[1]].strip():
            spans.append(Span(sp[0], sp[1], kind, field))

    if message_id == "tool.error_text":
        if message.strip():
            spans.append(Span(0, len(message), "tool-error-text"))
    elif message_id == "invalid":
        if message:
            spans.append(Span(0, len(message), "unparsed-line"))
    elif cls is None or cls.entry is None:
        # not classified: nothing is known about the text
        if message.strip():
            spans.append(Span(0, len(message), "unclassified-text"))
    elif mask in ("error_text", "error_stack") or (mask is None and key == "error"):
        # error text: the message part of a template that has one, else (for an
        # error-level record of a template not marked as fixed text) the whole text
        if mask == "error_text" and cls.span("message") is not None:
            grp("message", "error-text")
        elif mask == "error_stack" and cls.span("error_name") is not None:
            # "<Name>: <message>\n    at ..." -- everything after the error name
            end = cls.span("error_name")[1]
            if message[end:].strip():
                spans.append(Span(end, len(message), "error-text"))
        elif key == "error" and not cls.entry.fixed_text and message.strip():
            spans.append(Span(0, len(message), "error-text"))
    elif mask == "stderr":
        grp("stderr", "stderr")
    elif mask == "tool_error":
        grp("message", "tool-error-text")
    elif mask == "transport_options":
        hs = header_spans(message)
        for u in unparsed_options_url_spans(message):
            over = [h for h in hs if h.start < u.end and h.end > u.start]
            if over:  # one item for both, so no byte of either is printed
                u = Span(min([u.start] + [h.start for h in over]), max([u.end] + [h.end for h in over]), u.kind)
                hs = [h for h in hs if h not in over]
            spans.append(u)
        spans.extend(hs)
    elif mask == "env":
        spans.extend(env_spans(message))
    elif mask == "elicitation_request":
        spans.extend(json_string_span(message, "message", "elicitation-question"))
        # the schema's property names (= the answer's keys) are withheld with it
        spans.extend(json_object_span(message, "requestedSchema", "elicitation-schema", names=False))
    elif mask == "elicitation_response":
        spans.extend(json_object_span(message, "content", "elicitation-answer", names=False))
    elif mask == "channel_message":
        grp("content", "channel-message")
    elif mask == "server_output":
        grp("detail", "server-output")
    elif mask == "permission_rules":
        grp("rules", "permission-rules")
    elif mask == "config_headers":
        i = message.find("configHeaders=")
        if i != -1 and message[i + 14:].strip():
            spans.append(Span(i + 14, len(message), "http-header", "configHeaders"))
    # URLs anywhere in the message: the parts outside spans already withheld
    taken = sorted((o.start, o.end) for o in spans)
    for s in url_spans(message):
        pieces, a = [], s.start
        for o_start, o_end in taken:
            if o_end <= a or o_start >= s.end:
                continue
            if o_start > a:
                pieces.append((a, o_start))
            a = max(a, o_end)
        if a < s.end:
            pieces.append((a, s.end))
        for a, b in pieces:
            if message[a:b].strip():
                spans.append(s if (a, b) == (s.start, s.end) else Span(a, b, s.kind, s.field))
    return sorted(spans, key=lambda s: s.start)


def apply_spans(message: str, spans: list[Span], source: str,
                policy: SensitivePolicy) -> tuple[str, list[SensitiveItem]]:
    """Build the display text and the SensitiveItem list for message."""
    items: list[SensitiveItem] = []
    out: list[str] = []
    pos = 0
    for s in sorted(spans, key=lambda s: s.start):
        if s.start < pos:
            continue  # overlapping span: already covered
        raw = message[s.start:s.end]
        value = decode_json_fragment(raw) if s.json_escaped else raw
        item = make_item(s.kind, value, source, policy, s.field)
        items.append(item)
        out.append(message[pos:s.start])
        out.append(raw if policy.show else placeholder(item))
        pos = s.end
    out.append(message[pos:])
    return "".join(out), items
