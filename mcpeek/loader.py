"""Target discovery, driven by data/claude_code.yml.

The loader's job is purely to *find* artifacts on disk and hand back
resolved paths -- it does not parse transcript/session content (that is
parse.py's job). It is tolerant of missing files: a --target root that is
missing half the tree (e.g. no --debug logs, no backups) is normal, not an
error.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from typing import Iterable, Optional

import yaml

from . import safejson

_MANIFEST_PATH = Path(__file__).parent / "data" / "claude_code.yml"


@dataclass
class SessionFiles:
    session_uuid: str
    project_dir_encoded: str
    jsonl_path: Path
    subagent_dir: Optional[Path] = None
    tool_results_dir: Optional[Path] = None
    skip_names: set[str] = field(default_factory=set)  # sub-agent files that are symlinks leaving the target


@dataclass
class CacheRootFound:
    path: Path  # the claude-cli-nodejs directory (or its Windows "Cache" child)
    origin: str  # linux-default | macos-default | windows-default | cli-option | found-in-target
    status: str  # observed | static


@dataclass
class McpLogPath:
    path: Path
    cache_root: Path
    encoded_cwd: str
    server_dir: str  # folder suffix after "mcp-logs-"


@dataclass
class DebugPath:
    path: Path
    origin: str  # debug-dir | cli-option
    name_kind: str  # session | rotated | sdk | latest-copy | other
    session_id: Optional[str] = None  # from the file name, if it carries one
    allow_levelless: bool = False  # accept "<ISO> <msg>" lines without [LEVEL] (SDK host format)


@dataclass
class LatestFound:
    path: Path
    kind: str  # symlink | regular-file
    target: Optional[str] = None
    resolves_to: Optional[str] = None
    identical_to: Optional[str] = None


_UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
_DEBUG_NAME_RES = [
    ("session", re.compile(rf"^({_UUID})\.txt$")),
    ("rotated", re.compile(rf"^({_UUID})\.1\.txt$")),
    ("sdk", re.compile(rf"^sdk-({_UUID})\.txt$")),
]


def classify_debug_name(name: str) -> tuple[str, Optional[str]]:
    """Return (name_kind, session id from the name). sdk-<uuid> names carry a
    random id, not a session id."""
    for kind, rx in _DEBUG_NAME_RES:
        m = rx.match(name)
        if m:
            return kind, (m.group(1) if kind in ("session", "rotated") else None)
    return "other", None


@dataclass
class ProjectScopedFile:
    project_path: str  # project path on the examined host, as recorded (.claude.json key or transcript cwd)
    path: Path  # the file under the target root


@dataclass
class ProjectDirFound:
    path: str  # project path on the examined host
    sources: list[str]
    target_path: Optional[Path] = None  # the same folder under the target root (None: not inside HOME)
    in_target: bool = False


@dataclass
class SkippedLink:
    path: Path  # the symlink
    target: Optional[str]  # readlink() text
    looked_up_as: str  # what MCPeek was looking for there


@dataclass
class AliasFound:
    path: Path  # the path not read again
    target: Optional[str]  # readlink() text of the symlink on the way, if one was found
    same_as: Path  # the path that was read
    looked_up_as: str


@dataclass
class DiscoveredTarget:
    target_root: Path
    user_config_path: Optional[Path] = None
    backup_paths: list[Path] = field(default_factory=list)
    credentials_path: Optional[Path] = None
    user_grants_path: Optional[Path] = None
    user_grants_projects: list[str] = field(default_factory=list)  # projects at HOME: same settings.local.json
    project_grant_paths: list[ProjectScopedFile] = field(default_factory=list)
    project_mcp_manifest_paths: list[ProjectScopedFile] = field(default_factory=list)
    home: Optional[str] = None
    home_source: str = "not determined"
    project_dirs: list[ProjectDirFound] = field(default_factory=list)
    sessions: list[SessionFiles] = field(default_factory=list)
    debug_files: list[DebugPath] = field(default_factory=list)
    debug_latest: list[LatestFound] = field(default_factory=list)
    cache_roots: list[CacheRootFound] = field(default_factory=list)
    mcp_log_paths: list[McpLogPath] = field(default_factory=list)
    skipped_links: list[SkippedLink] = field(default_factory=list)
    aliases: list[AliasFound] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def load_manifest() -> dict:
    with open(_MANIFEST_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _manifest_entry(manifest: dict, artifact_id: str) -> dict:
    for a in manifest["artifacts"]:
        if a["id"] == artifact_id:
            return a
    raise KeyError(f"artifact id {artifact_id!r} not found in manifest")


def _read_project_cwds(user_config_path: Optional[Path]) -> list[str]:
    """Return the list of project cwd keys from .claude.json's "projects" map."""
    if user_config_path is None or not user_config_path.is_file():
        return []
    data = safejson.read_object(user_config_path, None)  # parse problems are reported by parse.py
    projects = data.get("projects") if isinstance(data, dict) else None
    if not isinstance(projects, dict):
        return []
    return [k for k in projects.keys() if isinstance(k, str) and k]


# ---------------------------------------------------------------------------
# HOME of the examined host
#
# Project paths in .claude.json and transcript cwd values are absolute paths
# on the examined host (e.g. /root/pi). The --target root stands for that
# host's HOME, so a project's own files (<project>/.claude/settings.local.json,
# <project>/.mcp.json) are found at <target>/<project path relative to HOME>.
# HOME itself is not a field of these files: it is given with --home or inferred.
# ---------------------------------------------------------------------------

_WINDOWS_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]|^\\\\")


def pure_path(p: str) -> PurePath:
    return PureWindowsPath(p) if _WINDOWS_PATH_RE.match(p) else PurePosixPath(p)


def path_below(path: str, home: str) -> Optional[tuple[str, ...]]:
    """Components of ``path`` below ``home``: () if both are the same folder,
    None if ``path`` is not inside ``home``."""
    pp, hp = pure_path(path), pure_path(home)
    if type(pp) is not type(hp) or not pp.is_absolute() or not hp.is_absolute():
        return None
    try:
        return pp.relative_to(hp).parts
    except ValueError:
        return None


def _conventional_home(path: str) -> Optional[str]:
    """/root, /home/<user>, /Users/<user>, /var/root or C:\\Users\\<user> containing path."""
    pp = pure_path(path)
    parts = pp.parts
    if isinstance(pp, PureWindowsPath):
        if len(parts) >= 3 and parts[1].lower() == "users":
            return str(PureWindowsPath(*parts[:3]))
        return None
    if len(parts) >= 2 and parts[1] == "root":
        return "/root"
    if len(parts) >= 3 and parts[1] in ("home", "Users"):
        return "/" + parts[1] + "/" + parts[2]
    if len(parts) >= 3 and parts[1] == "var" and parts[2] == "root":
        return "/var/root"
    return None


def _decode_conventional(encoded: str) -> Optional[str]:
    """Best-effort HOME from an encoded folder name (enc(cwd), lossy):
    "-root[-...]" -> /root, "-home-<user>[-...]" -> /home/<user>."""
    if encoded == "-root" or encoded.startswith("-root-"):
        return "/root"
    m = re.match(r"^-(home|Users)-([A-Za-z0-9]+)(?:-|$)", encoded)
    if m:
        return f"/{m.group(1)}/{m.group(2)}"
    return None


def _common_folder(paths: list[PurePath]) -> Optional[PurePath]:
    if not paths or len({type(p) for p in paths}) > 1:
        return None
    common = paths[0]
    for q in paths[1:]:
        while not (q == common or common in q.parents):
            if common == common.parent:
                return None
            common = common.parent
    return common


def _is_conventional_home(home: str) -> bool:
    return _conventional_home(home) == home


def infer_home_details(target_root: Path, project_paths: Iterable[str],
                       encoded_names: Iterable[str] = ()) -> tuple[Optional[str], str, list[str]]:
    """Infer HOME of the examined host. Returns (home, how it was determined,
    cautions for the examiner).

    1. Folder evidence: for every ancestor H of a project path, count the
       project paths P below H for which <target>/<P relative to H> is an
       existing folder. The H that maps the most project paths wins; ties go
       to the H under which the mapped paths have more components, then to
       the lexicographically smallest H.
    2. Without folder evidence: the conventional home location (/root,
       /home/<user>, /Users/<user>, C:\\Users\\<user>) that contains the most
       project paths (ties: lexicographically smallest).
    3. Otherwise the common parent folder of the project paths.
    4. Without any project path: a conventional home decoded from the encoded
       project folder names (lossy).

    A tie, a runner-up candidate, or a winner that is not a conventional home
    location is described in ``how`` and returned as a caution (the folder
    evidence can be coincidental; --home settles it).
    """
    paths = sorted({p for p in project_paths if p and pure_path(p).is_absolute()})
    advice = "give HOME with --home if this is wrong"
    if paths:
        n_paths = len(paths)
        pures = [pure_path(p) for p in paths]
        keyed = [(type(pp), tuple(x.casefold() if isinstance(pp, PureWindowsPath) else x for x in pp.parts), pp.parts)
                 for pp in pures]
        cands = {(t, k[:n]): pp_parts[:n] for t, k, pp_parts in keyed for n in range(1, len(k) + 1)}
        is_dir: dict[tuple[str, ...], bool] = {}
        scored = []
        for (t, ck), cparts in cands.items():
            mapped = depth = 0
            for t2, k2, parts2 in keyed:
                if t2 is not t or len(k2) <= len(ck) or k2[:len(ck)] != ck:
                    continue
                rel = parts2[len(ck):]
                if rel not in is_dir:
                    is_dir[rel] = target_root.joinpath(*rel).is_dir()
                if is_dir[rel]:
                    mapped += 1
                    depth += len(rel)
            if mapped:
                scored.append((-mapped, -depth, str(t(*cparts))))
        if scored:
            scored.sort()
            mapped, depth, h = scored[0]
            # Counted as in the `info` Project paths row: project paths below
            # HOME found as folders in the target; a project path that is HOME
            # itself (always the target root) is named separately, not counted.
            at_home = sum(1 for p in paths if path_below(p, h) == ())
            how = f"project folders found in the target: {-mapped} of {n_paths} project path(s) below HOME"
            if at_home:
                how += f", not counting {at_home} that is HOME itself (the target root)"
            cautions = []
            tied = [x[2] for x in scored[1:] if x[:2] == (mapped, depth)]
            runner = next((x for x in scored[1:] if x[:2] != (mapped, depth)), None)
            if tied:
                how += f"; tie with {', '.join(tied)} (alphabetical order decided)"
                cautions.append(f"HOME of the examined host: {', '.join([h] + tied)} each map {-mapped} of {n_paths} "
                                f"project path(s) to folders in the target at the same depth; {h} was taken "
                                f"(alphabetical order); {advice}")
            if runner is not None:
                how += f"; runner-up {runner[2]} ({-runner[0]} of {n_paths})"
                if not tied:
                    cautions.append(f"HOME of the examined host inferred as {h} ({-mapped} of {n_paths} project "
                                    f"path(s) found as folders below it in the target); runner-up {runner[2]} "
                                    f"({-runner[0]} of {n_paths}); {advice}")
            if not tied and not _is_conventional_home(h):
                cautions.append(f"HOME of the examined host inferred as {h}, which is not a conventional home "
                                f"location, from {-mapped} of {n_paths} project path(s) found as folders below it in "
                                f"the target (the match can be coincidental); {advice}")
            return h, how, cautions
        conv: dict[str, int] = {}
        for p in paths:
            c = _conventional_home(p)
            if c:
                conv[c] = conv.get(c, 0) + 1
        if conv:
            ranked = sorted((-n, h) for h, n in conv.items())
            n, h = ranked[0]
            at_home = sum(1 for p in paths if path_below(p, h) == ())
            below = sum(1 for p in paths if path_below(p, h))
            how = f"conventional home location of {-n} of {n_paths} project path(s)"
            if at_home:
                how += f", {at_home} of them HOME itself (the target root)"
            if below:
                how += f"; no folder of the {below} project path(s) below HOME found in the target"
            cautions = []
            tied = [x[1] for x in ranked[1:] if x[0] == n]
            runner = next((x for x in ranked[1:] if x[0] != n), None)
            if tied:
                how += f"; tie with {', '.join(tied)} (alphabetical order decided)"
                cautions.append(f"HOME of the examined host: {', '.join([h] + tied)} each contain {-n} of {n_paths} "
                                f"project path(s); {h} was taken (alphabetical order); {advice}")
            if runner is not None:
                how += f"; runner-up {runner[1]} ({-runner[0]} of {n_paths})"
                if not tied:
                    cautions.append(f"HOME of the examined host inferred as {h} ({-n} of {n_paths} project path(s)); "
                                    f"runner-up {runner[1]} ({-runner[0]} of {n_paths}); {advice}")
            return h, how, cautions
        common = _common_folder([pure_path(p).parent for p in paths])
        if common is not None and common != common.parent:
            return (str(common), "common parent folder of the project paths; no project folder found in the target",
                    [f"HOME of the examined host taken as {common}, the common parent folder of the project paths "
                     f"(no project folder found in the target, no conventional home location); {advice}"])
        return None, "not determined: the project paths share no folder below the file system root", []
    decoded = sorted({d for d in (_decode_conventional(e) for e in encoded_names) if d})
    if len(decoded) == 1:
        return decoded[0], "decoded from encoded project folder names (lossy); no project path recorded", []
    return None, "not determined: no project path recorded", []


_SCAN_SKIP = {".claude", ".git", "node_modules", "projects", "proc", "sys", "dev"}


def _files_identical(a: Path, b: Path) -> bool:
    try:
        if a.stat().st_size != b.stat().st_size:
            return False
        with open(a, "rb") as fa, open(b, "rb") as fb:
            while True:
                ca, cb = fa.read(1 << 20), fb.read(1 << 20)
                if ca != cb:
                    return False
                if not ca:
                    return True
    except OSError:
        return False


def _log_roots_under(cdir: Path) -> list[Path]:
    """A claude-cli-nodejs directory holds <enc-cwd>/mcp-logs-*/ directly
    (Linux, macOS) or under a "Cache" child (Windows)."""
    roots = [cdir]
    if (cdir / "Cache").is_dir():
        roots.append(cdir / "Cache")
    return roots


def _first_cwd(path: Path, max_lines: int = 200) -> Optional[str]:
    """cwd of the first transcript record that carries one (only the head of
    the file is read)."""
    try:
        with open(path, "rb") as f:
            for i, raw in enumerate(f):
                if i >= max_lines:
                    break
                if b'"cwd"' not in raw:
                    continue
                try:
                    rec = safejson.loads(raw.decode("utf-8", errors="replace"))
                except ValueError:
                    continue
                if isinstance(rec, dict) and isinstance(rec.get("cwd"), str) and rec["cwd"]:
                    return rec["cwd"]
    except OSError:
        return None
    return None


class TargetLoader:
    def __init__(
        self,
        target_root: str | Path,
        cache_dirs: Iterable[str | Path] = (),
        debug_files: Iterable[str | Path] = (),
        home: Optional[str] = None,
    ):
        self.target_root = Path(target_root)
        self.manifest = load_manifest()
        self.extra_cache_dirs = [Path(p) for p in cache_dirs]
        self.extra_debug_files = [Path(p) for p in debug_files]
        self.home = home
        # Folders whose content may be read: the target root and the folders
        # the examiner named. A symlink found while scanning is followed only
        # if it resolves inside one of them.
        self._given = [self.target_root] + self.extra_cache_dirs + [
            p if p.is_dir() else p.parent for p in self.extra_debug_files]
        self._roots: list[Path] = []
        for g in self._given:
            try:
                self._roots.append(g.resolve())
            except (OSError, RuntimeError):
                continue
        self._reported_links: set[str] = set()
        self._cli_cache_roots: list[tuple[Path, list[Path]]] = []
        self._cli_inside: dict[str, Path] = {}  # --cache-dir root -> the cache folder it lies inside
        # resolved path -> the path it is read under; resolved paths already read
        self._owner: dict[str, Path] = {}
        self._done: set[str] = set()

    # -- symlinks -----------------------------------------------------------

    def _inside(self, p: Path) -> bool:
        try:
            rp = p.resolve()
        except (OSError, RuntimeError):
            return False
        return any(rp == r or rp.is_relative_to(r) for r in self._roots)

    def readable(self, result: DiscoveredTarget, p: Path, looked_up_as: str) -> bool:
        """True if ``p`` stays inside the target root (or a folder named with
        --cache-dir / --debug-file) once symlinks are resolved. A symlink on
        the way that leads elsewhere is reported once and not followed."""
        if self._inside(p):
            return True
        for a in [*reversed(p.parents), p]:
            if any(a == g or a in g.parents for g in self._given):
                continue  # at or above a folder the examiner named
            if a.is_symlink() and not self._inside(a):
                key = str(a)
                if key not in self._reported_links:
                    self._reported_links.add(key)
                    try:
                        link_target: Optional[str] = os.readlink(a)
                    except OSError:
                        link_target = None
                    result.skipped_links.append(SkippedLink(a, link_target, looked_up_as))
                    result.warnings.append(f"symlink not followed: {a} -> {link_target} (leads outside the target "
                                           f"root; looked up as {looked_up_as})")
                return False
        return True

    def _behind_skipped_link(self, p: Path) -> bool:
        """True if p lies below a symlink that was reported as not followed."""
        return any(Path(k) == p or Path(k) in p.parents for k in self._reported_links)

    # -- aliases: one file or folder reached under two paths -----------------

    def _symlink_on_way(self, p: Path) -> Optional[Path]:
        """The first symlink on the way from a folder the examiner named to p
        (p included), if any."""
        for a in [*reversed(p.parents), p]:
            if any(a == g or a in g.parents for g in self._given):
                continue
            if a.is_symlink():
                return a
        return None

    @staticmethod
    def _key(p: Path) -> str:
        try:
            return str(p.resolve())
        except (OSError, RuntimeError):
            return str(p.absolute())

    def _first_visit(self, result: DiscoveredTarget, p: Path, looked_up_as: str) -> bool:
        """True the first time the file or folder p resolves to is met. A
        different path to it (through a symlink inside the target) is reported
        as an alias and not read again."""
        key = self._key(p)
        owner = self._owner.setdefault(key, p)
        if owner != p:
            link = self._symlink_on_way(p) or self._symlink_on_way(owner)
            target: Optional[str] = None
            if link is not None:
                try:
                    target = os.readlink(link)
                except OSError:
                    target = None
            result.aliases.append(AliasFound(p, target, owner, looked_up_as))
            via = f" (symlink {link} -> {target})" if link is not None else ""
            result.warnings.append(f"{p} is the same {looked_up_as} as {owner}{via}; read once, as {owner}")
            return False
        if key in self._done:
            return False
        self._done.add(key)
        return True

    def _unique(self, result: DiscoveredTarget, paths: list[Path], looked_up_as: str) -> list[Path]:
        """paths without aliases, in their order. Among paths that resolve to
        the same file or folder, one without a symlink on the way is read."""
        for p in sorted(paths, key=lambda x: (self._symlink_on_way(x) is not None, str(x))):
            self._owner.setdefault(self._key(p), p)
        return [p for p in paths if self._first_visit(result, p, looked_up_as)]

    # -- MCP logs ---------------------------------------------------------

    def _discover_cache_roots(self, result: DiscoveredTarget) -> None:
        root = self.target_root
        entry = _manifest_entry(self.manifest, "mcp_logs")

        def add(p: Path, origin: str, status: str) -> list[Path]:
            added = []
            for r in _log_roots_under(p):
                added.append(r)
                if self._first_visit(result, r, "MCP log cache folder"):
                    result.cache_roots.append(CacheRootFound(r, origin, status))
            return added

        for loc in entry["locations"]:
            p = root / loc["path"]
            if p.is_dir() and self.readable(result, p, "MCP log cache folder"):
                add(p, loc["origin"], loc["status"])
        for p in self.extra_cache_dirs:
            cand = None
            if (p / "claude-cli-nodejs").is_dir():
                cand = p / "claude-cli-nodejs"
            elif p.is_dir():
                cand = p
            if cand is None:
                result.warnings.append(f"--cache-dir {str(p)!r} is not a directory")
                continue
            self._cli_cache_roots.append((p, add(cand, "cli-option", "observed")))
        # bounded scan for relocated caches (e.g. XDG_CACHE_HOME=~/altcache):
        # <target>/claude-cli-nodejs and <target>/*/claude-cli-nodejs. A
        # symlink on the way that leads outside the target is reported.
        depth = int(entry.get("scan_depth", 2))
        level = [root] if root.is_dir() else []
        for i in range(depth):
            nxt: list[Path] = []
            for d in level:
                try:
                    children = sorted(c for c in d.iterdir() if c.is_dir())
                except OSError:
                    continue
                for c in children:
                    if c.name == "claude-cli-nodejs":
                        if self.readable(result, c, "MCP log cache folder"):
                            add(c, "found-in-target", "observed")
                    elif c.name not in _SCAN_SKIP and i + 1 < depth:
                        if not c.is_symlink() or self.readable(result, c, "folder searched for a relocated MCP "
                                                                          "log cache"):
                            nxt.append(c)
            level = nxt
        self._merge_nested_cli_roots(result)

    def _merge_nested_cli_roots(self, result: DiscoveredTarget) -> None:
        """A --cache-dir that is a project or server folder of a cache folder
        also found (claude-cli-nodejs/<project>, .../mcp-logs-<server>) is
        read as part of that folder, not as a second cache folder: that would
        claim the folder first and hide its log files from the outer one."""
        keys = {id(cr): Path(self._key(cr.path)) for cr in result.cache_roots}

        def outer(cr: CacheRootFound) -> Optional[CacheRootFound]:
            k, best = keys[id(cr)], None
            for o in result.cache_roots:
                ko = keys[id(o)]
                if ko in k.parents and len(k.parts) - len(ko.parts) <= 2 and (
                        best is None or len(ko.parts) > len(keys[id(best)].parts)):
                    best = o
            return best

        merged: dict[int, CacheRootFound] = {}
        for cr in result.cache_roots:
            if cr.origin == "cli-option":
                o, seen = outer(cr), 0
                while o is not None and o.origin == "cli-option" and outer(o) is not None and seen < 8:
                    o, seen = outer(o), seen + 1
                if o is not None:
                    merged[id(cr)] = o
        if not merged:
            return
        for i, (given, roots) in enumerate(self._cli_cache_roots):
            new_roots = []
            for r in roots:
                cr = next((x for x in result.cache_roots if x.path == r and id(x) in merged), None)
                if cr is None:
                    new_roots.append(r)
                    continue
                o = merged[id(cr)]
                key = self._key(r)
                self._done.discard(key)
                if self._owner.get(key) == r:
                    del self._owner[key]
                self._cli_inside[str(r)] = o.path
                result.warnings.append(f"--cache-dir {str(given)!r} lies inside the MCP log cache folder "
                                       f"{str(o.path)!r} (a project or server folder of it); its files are read as "
                                       "part of that folder")
                new_roots.append(r)
            self._cli_cache_roots[i] = (given, new_roots)
        result.cache_roots = [cr for cr in result.cache_roots if id(cr) not in merged]

    def _discover_mcp_logs(self, result: DiscoveredTarget) -> None:
        for cr in result.cache_roots:
            try:
                cwd_dirs = sorted(p for p in cr.path.iterdir() if p.is_dir())
            except OSError:
                continue
            cwd_dirs = self._unique(result, [d for d in cwd_dirs if self.readable(result, d, "MCP log project folder")],
                                    "MCP log project folder")
            for cwd_dir in cwd_dirs:
                log_dirs = [d for d in sorted(cwd_dir.glob("mcp-logs-*"))
                            if d.is_dir() and self.readable(result, d, "MCP log folder")]
                for log_dir in self._unique(result, log_dirs, "MCP log folder"):
                    others = 0
                    files = []
                    for f in sorted(log_dir.iterdir()):
                        if f.is_file() and f.suffix == ".jsonl":
                            if self.readable(result, f, "MCP log file"):
                                files.append(f)
                        else:
                            others += 1
                    for f in self._unique(result, files, "MCP log file"):
                        result.mcp_log_paths.append(
                            McpLogPath(f, cr.path, cwd_dir.name, log_dir.name[len("mcp-logs-"):])
                        )
                    if others:
                        result.warnings.append(f"{log_dir}: {others} entr(y/ies) that are not .jsonl files (not parsed)")
        for given, roots in self._cli_cache_roots:
            keys = {self._key(r) for r in roots}
            inside = [Path(self._key(r)) for r in roots if str(r) in self._cli_inside]
            if any(self._key(m.cache_root) in keys or any(k in Path(self._key(m.path)).parents for k in inside)
                   for m in result.mcp_log_paths):
                continue
            hint = ""
            if given.name.startswith("mcp-logs-"):
                hint = (f" (it looks like a server log folder claude-cli-nodejs/<project>/mcp-logs-<server>; pass "
                        f"{str(given.parent.parent)!r}, the claude-cli-nodejs folder two levels up, or its parent)")
            elif any(given.glob("mcp-logs-*")):
                hint = (f" (it looks like a project folder claude-cli-nodejs/<project>; pass {str(given.parent)!r}, "
                        "the claude-cli-nodejs folder one level up, or its parent)")
            result.warnings.append(
                f"--cache-dir {str(given)!r}: no <project>/mcp-logs-<server>/*.jsonl found below it{hint}; expected "
                "the cache folder that holds claude-cli-nodejs/ (the XDG_CACHE_HOME value) or claude-cli-nodejs/ itself"
            )

    # -- debug files -------------------------------------------------------

    def _add_debug_dir(self, result: DiscoveredTarget, ddir: Path, origin: str) -> None:
        patterns = ["*.txt"] + (["*.log"] if origin == "cli-option" else [])
        txts: list[Path] = []
        for pat in patterns:
            # a symlink that leaves the target is reported whatever it points to
            txts += sorted(p for p in ddir.glob(pat)
                           if (p.is_file() or p.is_symlink()) and self.readable(result, p, "--debug file")
                           and p.is_file())
        # any other symlink in the folder (not a debug file by name, e.g.
        # "sub -> /elsewhere") is listed too when it leaves the target
        named = {p.name for pat in patterns for p in ddir.glob(pat)}
        try:
            others = sorted(p for p in ddir.iterdir()
                            if p.is_symlink() and p.name != "latest" and p.name not in named)
        except OSError:
            others = []
        for p in others:
            self.readable(result, p, "entry of the --debug folder")
        for p in self._unique(result, txts, "--debug file"):
            self._add_debug_file(result, p, origin, visited=True)
        latest = ddir / "latest"
        if latest.is_symlink():
            try:
                target = os.readlink(latest)  # never followed
            except OSError:
                target = None
            info = LatestFound(path=latest, kind="symlink", target=target)
            if target:
                cand = ddir / Path(target).name
                if cand.is_file() and not cand.is_symlink():
                    info.resolves_to = str(cand)
            result.debug_latest.append(info)
        elif latest.is_file():
            info = LatestFound(path=latest, kind="regular-file")
            for p in txts:
                if _files_identical(latest, p):
                    info.identical_to = str(p)
                    break
            result.debug_latest.append(info)
            if info.identical_to is None:
                self._add_debug_file(result, latest, origin, name_kind="latest-copy")

    def _add_debug_file(self, result: DiscoveredTarget, p: Path, origin: str,
                        name_kind: Optional[str] = None, visited: bool = False) -> None:
        if not visited and not self._first_visit(result, p, "--debug file"):
            return
        kind, sid = classify_debug_name(p.name)
        if name_kind:
            kind, sid = name_kind, None
        result.debug_files.append(
            DebugPath(
                path=p,
                origin=origin,
                name_kind=kind,
                session_id=sid,
                allow_levelless=(kind in ("sdk", "other", "latest-copy") or origin == "cli-option"),
            )
        )

    # -- files at fixed places ---------------------------------------------

    def _file(self, result: DiscoveredTarget, p: Path, what: str, missing: Optional[str]) -> Optional[Path]:
        if p.is_file():
            return p if self.readable(result, p, what) and self._first_visit(result, p, what) else None
        if missing and not self._behind_skipped_link(p):
            result.warnings.append(missing)
        return None

    # -- projects ------------------------------------------------------------

    def _discover_projects(self, result: DiscoveredTarget) -> None:
        sources: dict[str, list[str]] = {}
        for cwd in _read_project_cwds(result.user_config_path):
            sources.setdefault(cwd, []).append(".claude.json projects")
        for sf in result.sessions:
            cwd = _first_cwd(sf.jsonl_path)
            if cwd and "transcript cwd" not in sources.setdefault(cwd, []):
                sources[cwd].append("transcript cwd")
        encoded = sorted({sf.project_dir_encoded for sf in result.sessions}
                         | {m.encoded_cwd for m in result.mcp_log_paths})
        if self.home:
            home: Optional[str] = self.home
            how = "--home option"
        else:
            home, how, cautions = infer_home_details(self.target_root, list(sources), encoded)
            result.warnings.extend(cautions)
        result.home, result.home_source = home, how

        pg = _manifest_entry(self.manifest, "project_grants")
        pm = _manifest_entry(self.manifest, "project_mcp_manifest")
        exclude = pm.get("exclude_path_contains", [])
        grants: dict[str, ProjectScopedFile] = {}
        manifests: dict[str, ProjectScopedFile] = {}

        user_key = self._key(result.user_grants_path) if result.user_grants_path is not None else None

        def put(store: dict[str, ProjectScopedFile], proj: str, path: Path, what: str) -> None:
            key = self._key(path)
            if what == "project settings.local.json" and key == user_key:
                # a symlink to the user-scope file: listed once, with both scopes
                self._first_visit(result, path, what)
                if proj not in result.user_grants_projects:
                    result.user_grants_projects.append(proj)
            elif key in store:
                if store[key].path != path:
                    self._first_visit(result, path, what)
                store[key].project_path += ", " + proj
            else:
                self._owner.setdefault(key, path)
                self._done.add(key)
                store[key] = ProjectScopedFile(proj, path)

        for proj in sorted(sources):
            d = ProjectDirFound(proj, sources[proj])
            result.project_dirs.append(d)
            parts = path_below(proj, home) if home else None
            if parts is None:
                if home is not None:
                    result.warnings.append(
                        f"project path {proj!r} is outside HOME {home!r} of the examined host; its project-scope "
                        "settings.local.json and .mcp.json are not under the target root")
                continue
            tdir = self.target_root.joinpath(*parts)
            d.target_path = tdir
            d.in_target = tdir.is_dir()
            if not d.in_target:
                continue
            if not parts:
                # The project is HOME itself: its .claude/settings.local.json is
                # the user-scope file, listed once with both scopes.
                if result.user_grants_path is not None and proj not in result.user_grants_projects:
                    result.user_grants_projects.append(proj)
            else:
                gp = tdir / pg["relative_path"]
                if gp.is_file() and self.readable(result, gp, "project settings.local.json"):
                    put(grants, proj, gp, "project settings.local.json")
            mp = tdir / pm["relative_path"]
            if (mp.is_file() and not any(e in str(mp) for e in exclude)
                    and self.readable(result, mp, "project .mcp.json")):
                put(manifests, proj, mp, "project .mcp.json")
        result.project_grant_paths = list(grants.values())
        result.project_mcp_manifest_paths = list(manifests.values())
        if home is None and sources:
            result.warnings.append(f"HOME of the examined host {how}; project-scope settings.local.json and .mcp.json "
                                   "were not looked up (give HOME with --home)")

    def discover(self) -> DiscoveredTarget:
        root = self.target_root
        result = DiscoveredTarget(target_root=root)

        if not root.is_dir():
            result.warnings.append(f"target root does not exist or is not a directory: {root}")
            return result

        # .claude itself as a symlink that leaves the target: reported once,
        # for everything below it
        claude_dir = root / ".claude"
        if claude_dir.is_symlink():
            self.readable(result, claude_dir, ".claude folder (transcripts, credentials, settings, backups, "
                                              "--debug files)")

        # user_config
        uc = _manifest_entry(self.manifest, "user_config")
        p = root / uc["path"]
        result.user_config_path = self._file(result, p, ".claude.json", f"no .claude.json found at {p}")

        # config_backups
        bk = _manifest_entry(self.manifest, "config_backups")
        bdir = root / bk["path"]
        if bdir.is_dir() and self.readable(result, bdir, "config backups"):
            result.backup_paths = self._unique(result, sorted(b for b in bdir.glob(bk["glob"])
                                                              if b.is_file() and self.readable(result, b, "config backup")),
                                               "config backup")
        elif not bdir.is_dir() and not self._behind_skipped_link(bdir):
            result.warnings.append(f"no backups directory at {bdir}")

        # credentials
        cr = _manifest_entry(self.manifest, "credentials")
        cp = root / cr["path"]
        result.credentials_path = self._file(result, cp, ".credentials.json", f"no .credentials.json found at {cp}")

        # user_grants
        ug = _manifest_entry(self.manifest, "user_grants")
        gp = root / ug["path"]
        result.user_grants_path = self._file(result, gp, "user settings.local.json",
                                             f"no user-scope settings.local.json found at {gp}")

        # sessions (two on-disk shapes, merged per session_uuid)
        se = _manifest_entry(self.manifest, "sessions")
        sessions_root = root / se["path"]
        if sessions_root.is_dir() and self.readable(result, sessions_root, "transcript folder"):
            project_dirs = [p for p in sorted(sessions_root.iterdir())
                            if p.is_dir() and self.readable(result, p, "transcript folder")]
            for project_dir in self._unique(result, project_dirs, "transcript folder"):
                jsonls = [j for j in sorted(project_dir.glob("*.jsonl"))
                          if j.is_file() and self.readable(result, j, "session transcript")]
                for jsonl_path in self._unique(result, jsonls, "session transcript"):
                    session_uuid = jsonl_path.stem
                    companion_dir = project_dir / session_uuid
                    subagent_dir = companion_dir / "subagents"
                    tool_results_dir = companion_dir / "tool-results"
                    sf = SessionFiles(
                        session_uuid=session_uuid,
                        project_dir_encoded=project_dir.name,
                        jsonl_path=jsonl_path,
                        subagent_dir=subagent_dir if (subagent_dir.is_dir() and self.readable(
                            result, subagent_dir, "sub-agent folder") and self._first_visit(
                            result, subagent_dir, "sub-agent folder")) else None,
                        tool_results_dir=tool_results_dir if (tool_results_dir.is_dir() and self.readable(
                            result, tool_results_dir, "spilled tool results folder")) else None,
                    )
                    if sf.subagent_dir is not None:
                        files = []
                        for f in sorted(sf.subagent_dir.iterdir()):
                            if f.is_symlink() and not self.readable(result, f, "sub-agent file"):
                                sf.skip_names.add(f.name)
                            else:
                                files.append(f)
                        kept = set(self._unique(result, files, "sub-agent file"))
                        sf.skip_names.update(f.name for f in files if f not in kept)
                    result.sessions.append(sf)
        elif not sessions_root.is_dir() and not self._behind_skipped_link(sessions_root):
            result.warnings.append(f"no sessions directory at {sessions_root}")
        # transcripts of another config folder (a relocated CLAUDE_CONFIG_DIR)
        # are not read: say where they are
        for cfg_dir in sorted(root.glob(".claude?*")):
            if cfg_dir.name == ".claude" or not cfg_dir.is_dir():
                continue
            other = cfg_dir / se["path"].split("/", 1)[-1]
            if other.is_dir() and self._inside(other):
                result.warnings.append(f"{other}: transcript folder of a config folder other than .claude "
                                       "(for example a relocated CLAUDE_CONFIG_DIR); not read (see README, Scope "
                                       "and limitations)")
            other_cfg = cfg_dir / ".claude.json"
            if other_cfg.is_file() and self._inside(other_cfg):
                result.warnings.append(f"{other_cfg}: .claude.json of a config folder other than .claude "
                                       "(for example a relocated CLAUDE_CONFIG_DIR); not read (see README, Scope "
                                       "and limitations)")

        # debug logs (default folder, then any --debug-file paths)
        dl = _manifest_entry(self.manifest, "debug_logs")
        ddir = root / dl["path"]
        if ddir.is_dir() and self.readable(result, ddir, "--debug folder"):
            self._add_debug_dir(result, ddir, "debug-dir")
        elif not ddir.is_dir() and not self._behind_skipped_link(ddir):
            result.warnings.append(f"no debug folder at {ddir} (expected unless debug mode was enabled)")
        for p in self.extra_debug_files:
            if p.is_dir():
                self._add_debug_dir(result, p, "cli-option")
            elif p.is_file():
                self._add_debug_file(result, p, "cli-option")
            else:
                result.warnings.append(f"--debug-file {str(p)!r} does not exist")

        # per-server MCP logs
        self._discover_cache_roots(result)
        self._discover_mcp_logs(result)
        if not result.cache_roots:
            result.warnings.append(
                "no claude-cli-nodejs cache folder found (MCP logs); use --cache-dir if XDG_CACHE_HOME was relocated"
            )

        # HOME of the examined host, project folders and their project-scope files
        self._discover_projects(result)
        return result
