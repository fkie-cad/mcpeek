"""Defensive JSON helpers for evidence files.

Evidence is read as found: a file can be truncated, hold invalid UTF-8, nest
deeper than the json module can decode (RecursionError, not ValueError), or
carry any JSON type where a string, array or object is expected. These
helpers turn each of those into a warning that names the file and the field,
so one bad file or field never stops a run.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

MISSING = object()  # read_file(): the file could not be read or parsed


def loads(text: str) -> Any:
    """json.loads that reports every parse failure as ValueError."""
    try:
        return json.loads(text)
    except RecursionError as exc:
        raise ValueError("nested too deeply to decode") from exc


def dumps(obj: Any, **kwargs: Any) -> str:
    """json.dumps that never raises (a value it cannot serialize becomes a marker)."""
    try:
        return json.dumps(obj, **kwargs)
    except (TypeError, ValueError, RecursionError):
        return "[value not serializable]"


def decode(raw: bytes) -> tuple[str, bool]:
    """UTF-8 text of raw bytes and whether replacement characters were needed."""
    try:
        return raw.decode("utf-8"), False
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace"), True


def kind(value: Any) -> str:
    """JSON type of a value, for warnings."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, (int, float)):
        return "a number"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, list):
        return "an array"
    if isinstance(value, dict):
        return "an object"
    return type(value).__name__


DEPTH_LIMIT = 64
TOO_DEEP = f"[nested deeper than {DEPTH_LIMIT} levels: not shown]"


def limit_depth(value: Any, max_depth: int = DEPTH_LIMIT) -> Any:
    """Copy of a JSON value that MCPeek keeps for output (discoveryState,
    capabilities) with arrays and objects below ``max_depth`` levels replaced
    by a marker: a parseable but deeply nested value would otherwise break
    serialization."""
    def walk(v: Any, depth: int) -> Any:
        if isinstance(v, dict):
            return TOO_DEEP if depth >= max_depth else {k: walk(x, depth + 1) for k, x in v.items()}
        if isinstance(v, list):
            return TOO_DEEP if depth >= max_depth else [walk(x, depth + 1) for x in v]
        return v

    return walk(value, 0)


def _warn(warnings: Optional[list[str]], text: str) -> None:
    if warnings is not None:
        warnings.append(text)


def read_file(path: Path, warnings: Optional[list[str]]) -> Any:
    """Parsed content of a JSON file, or MISSING (reported) if it cannot be
    read or parsed. Invalid UTF-8 is decoded with replacement characters
    (reported)."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        _warn(warnings, f"{path} exists but could not be read: {exc}")
        return MISSING
    text, replaced = decode(raw)
    if replaced:
        _warn(warnings, f"{path}: not valid UTF-8 (decoded with replacement characters)")
    try:
        return loads(text)
    except ValueError as exc:
        _warn(warnings, f"{path} exists but could not be parsed as JSON: {exc}")
        return MISSING


def read_object(path: Path, warnings: Optional[list[str]]) -> Optional[dict]:
    """A JSON file whose top level must be an object; None (reported) otherwise."""
    data = read_file(path, warnings)
    if data is MISSING:
        return None
    if not isinstance(data, dict):
        _warn(warnings, f"{path}: top level is {kind(data)}, not a JSON object (ignored)")
        return None
    return data


def text(value: Any, label: str, warnings: Optional[list[str]]) -> Optional[str]:
    """A value that should be a string: a string as it is, a number or boolean
    as its JSON text (reported), null as None, an array or object ignored
    (reported). ``label`` names the file and field."""
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, (bool, int, float)):
        _warn(warnings, f"{label} is {kind(value)}, not a string (shown as text)")
        return dumps(value)
    _warn(warnings, f"{label} is {kind(value)}, not a string (ignored)")
    return None


def object_field(value: Any, label: str, warnings: Optional[list[str]]) -> Optional[dict]:
    """A value that should be an object: None (reported unless null) otherwise."""
    if isinstance(value, dict):
        return value
    if value is not None:
        _warn(warnings, f"{label} is {kind(value)}, not an object (ignored)")
    return None


def list_field(value: Any, label: str, warnings: Optional[list[str]]) -> Optional[list]:
    """A value that should be an array: None (reported unless null) otherwise."""
    if isinstance(value, list):
        return value
    if value is not None:
        _warn(warnings, f"{label} is {kind(value)}, not an array (ignored)")
    return None
