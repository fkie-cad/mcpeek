"""Message catalog for the per-server MCP log and the --debug file.

Loads data/claude_code_log_messages.yml and classifies message strings.
Nothing here interprets a message: classification only names the template
a message was produced from and extracts its fields.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional

import yaml

_CATALOG_PATH = Path(__file__).parent / "data" / "claude_code_log_messages.yml"

UNCLASSIFIED = "unclassified"
REDACTED_MARK = "[REDACTED]"


@dataclass(frozen=True)
class CatalogEntry:
    id: str
    key: str  # debug | error | any   (MCP log); or level for debug-file lines
    category: str
    status: str
    regex: re.Pattern
    mask: Optional[str]
    first_word: Optional[str]  # leading literal word of the pattern, if any
    fixed_text: bool = False  # the template holds only fixed text and names


@dataclass(frozen=True)
class Classification:
    entry: Optional[CatalogEntry]
    match: Optional[re.Match]
    first_word_masked: bool = False
    # When first_word_masked, the match ran on "<word><rest>" instead of
    # "[REDACTED]<rest>"; shift maps match offsets back to the original text.
    shift: int = 0

    @property
    def id(self) -> str:
        return self.entry.id if self.entry else UNCLASSIFIED

    @property
    def category(self) -> str:
        return self.entry.category if self.entry else UNCLASSIFIED

    @property
    def status(self) -> str:
        return self.entry.status if self.entry else UNCLASSIFIED

    @property
    def mask(self) -> Optional[str]:
        return self.entry.mask if self.entry else None

    def fields(self) -> dict[str, str]:
        if not self.match:
            return {}
        out = {}
        for k, v in self.match.groupdict().items():
            if v is None:
                continue
            if self.first_word_masked and self.match.start(k) == 0:
                continue  # value was masked by the CLI's redactor
            out[k] = v
        return out

    def span(self, group: str) -> Optional[tuple[int, int]]:
        """Span of a named group in the ORIGINAL message, or None."""
        if not self.match or group not in self.match.groupdict():
            return None
        if self.match.group(group) is None:
            return None
        start, end = self.match.span(group)
        if self.first_word_masked:
            if start == 0:
                return None
            start, end = start + self.shift, end + self.shift
        return start, end


_LEADING_WORD_RE = re.compile(r"^\^([A-Za-z][A-Za-z0-9-]*)(?= |\\| )")


def _first_literal_word(pattern: str) -> Optional[str]:
    m = _LEADING_WORD_RE.match(pattern)
    return m.group(1) if m else None


def _compile(entries: list[dict], key_field: str) -> tuple[CatalogEntry, ...]:
    out = []
    for e in entries:
        out.append(
            CatalogEntry(
                id=e["id"],
                key=e.get(key_field, "any"),
                category=e["category"],
                status=e.get("status", "static"),
                regex=re.compile(e["pattern"]),
                mask=e.get("mask"),
                first_word=_first_literal_word(e["pattern"]),
                fixed_text=bool(e.get("fixed_text", False)),
            )
        )
    return tuple(out)


@lru_cache(maxsize=1)
def _load() -> dict:
    with open(_CATALOG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


@lru_cache(maxsize=1)
def mcp_entries() -> tuple[CatalogEntry, ...]:
    return _compile(_load()["mcp_log_messages"], "key")


@lru_cache(maxsize=1)
def debug_line_entries() -> tuple[CatalogEntry, ...]:
    return _compile(_load()["debug_file_lines"], "level")


def classify_mcp_message(key: str, message: str) -> Classification:
    """Classify an MCP-log message (record key 'debug' or 'error')."""
    for entry in mcp_entries():
        if entry.key != "any" and entry.key != key:
            continue
        m = entry.regex.match(message)
        if m:
            return Classification(entry, m)
    return Classification(None, None)


def classify_mirror_text(key: str, text: str) -> Classification:
    """Classify the text of a debug-file mirror line.

    The CLI's debug redactor masks the first word of DEBUG mirror lines when
    the server name contains a keyword such as "secret" or "token"
    ('MCP server "secretsrv": [REDACTED] connection with timeout ...'). If the
    text starts with the marker, retry with each candidate leading word.
    """
    c = classify_mcp_message(key, text)
    if c.entry is not None or not text.startswith(REDACTED_MARK):
        return c
    rest = text[len(REDACTED_MARK):]
    candidates = sorted({e.first_word for e in mcp_entries() if e.first_word}) + ["UNKNOWN"]
    for word in candidates:
        c2 = classify_mcp_message(key, word + rest)
        if c2.entry is not None:
            return Classification(
                c2.entry, c2.match, first_word_masked=True, shift=len(REDACTED_MARK) - len(word)
            )
    return c


def classify_debug_line(level: Optional[str], message: str) -> Classification:
    for entry in debug_line_entries():
        if entry.key not in ("any", level):
            continue
        m = entry.regex.match(message)
        if m:
            return Classification(entry, m)
    return Classification(None, None)
