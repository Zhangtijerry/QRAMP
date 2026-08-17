# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Ti Zhang
"""qramp.collectors.tsquery — shared tree-sitter query engine.

The "what to look for in the source tree" is expressed declaratively in
``.scm`` query files (one per language, versioned alongside the code). This
module loads a grammar, compiles its query file, runs it over a source file
and yields, for each match, a simple dict mapping capture name -> text (plus
the anchor node for line numbers). The language-specific collector then only
has to *interpret* those captures into CryptoAssets — it no longer walks the
tree by hand.

Grammars and the tree-sitter runtime are optional dependencies. If a grammar
is not importable the engine reports unavailable and the collector degrades to
yielding nothing, exactly as before.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

# query files live next to this module
QUERY_DIR = os.path.join(os.path.dirname(__file__), "queries")

# grammar module name per language key
_GRAMMARS = {
    "java": "tree_sitter_java",
    "go": "tree_sitter_go",
    "python": "tree_sitter_python",
    "rust": "tree_sitter_rust",
    "c": "tree_sitter_c",
}


def _discover_project_query_dir(start: str | None = None) -> str | None:
    """Walk upward from `start` (cwd by default) looking for a
    ``.qramp/queries`` directory, so a site can drop query files at the root of
    its repository without any configuration."""
    d = os.path.abspath(start or os.getcwd())
    while True:
        candidate = os.path.join(d, ".qramp", "queries")
        if os.path.isdir(candidate):
            return candidate
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


@dataclass
class Match:
    """One query match. `caps` maps capture name -> text of the first node with
    that name; `nodes` keeps the raw first node per capture (for line numbers);
    `line` is the 1-based line of the @site (or @call) anchor."""
    caps: dict = field(default_factory=dict)
    nodes: dict = field(default_factory=dict)
    line: int = 0
    pattern: int = 0
    settings: dict = field(default_factory=dict)   # from #set! directives (site queries)


class QueryEngine:
    """Compiles the tree-sitter query for a language.

    Site operators can extend or replace the built-in detection rules without
    touching code. Resolution, highest precedence first:

      1. an explicit ``query_dir`` argument (or the ``QRAMP_QUERY_DIR`` env var);
      2. a project-local ``.qramp/queries/`` directory discovered upward from
         the current working directory.

    For a given language the engine looks for ``<language>.scm`` (full replace)
    and ``<language>.extra.scm`` (append to the built-in). By default a site
    file *extends* the built-in rules (append), which is the safe behaviour — a
    site adds patterns without silently losing the defaults. A full
    ``<language>.scm`` in the override directory replaces the built-in entirely,
    for sites that want complete control.
    """

    def __init__(self, language: str, query_dir: str | None = None):
        self.language = language
        self._override_dir = query_dir or os.environ.get("QRAMP_QUERY_DIR") \
            or _discover_project_query_dir()
        self.available = False
        self._reason = None
        self._parser = None
        self._query = None
        self.sources: list[dict] = []       # provenance of each .scm merged in
        self._load()

    def _resolve_scm(self) -> tuple[str, list[dict]]:
        """Return (merged_scm_text, provenance). Built-in first, then any site
        extension appended; a site full-replace file supersedes the built-in."""
        builtin = os.path.join(QUERY_DIR, f"{self.language}.scm")
        parts: list[str] = []
        prov: list[dict] = []

        override_full = replaced = None
        override_extra = None
        if self._override_dir and os.path.isdir(self._override_dir):
            f_full = os.path.join(self._override_dir, f"{self.language}.scm")
            f_extra = os.path.join(self._override_dir, f"{self.language}.extra.scm")
            if os.path.exists(f_full):
                override_full = f_full
            if os.path.exists(f_extra):
                override_extra = f_extra

        if override_full:
            parts.append(open(override_full, encoding="utf-8").read())
            prov.append({"role": "replace", "path": override_full})
            replaced = True
        elif os.path.exists(builtin):
            parts.append(open(builtin, encoding="utf-8").read())
            prov.append({"role": "builtin", "path": builtin})

        if override_extra:
            parts.append("\n; --- site extension ---\n"
                         + open(override_extra, encoding="utf-8").read())
            prov.append({"role": "extend", "path": override_extra})

        if not parts:
            return "", []
        _ = replaced
        return "\n".join(parts), prov

    def _load(self):
        modname = _GRAMMARS.get(self.language)
        if modname is None:
            self._reason = f"no grammar mapping for {self.language}"
            return
        try:
            import importlib
            from tree_sitter import Language, Parser, Query, QueryCursor  # noqa: F401
            grammar = importlib.import_module(modname)
            lang = Language(grammar.language())
            self._Query = Query
            self._QueryCursor = QueryCursor
            self._lang = lang
            self._parser = Parser(lang)
        except Exception as e:                          # pragma: no cover
            self._reason = f"tree-sitter grammar '{modname}' not installed ({e})"
            return

        scm, prov = self._resolve_scm()
        if not scm.strip():
            self._reason = f"no query file for {self.language}"
            return
        try:
            self._scm = scm
            self._query = Query(lang, scm)
            self.sources = prov
        except Exception as e:
            # a broken site query must not take down the collector: fall back to
            # the built-in alone and report the problem.
            self._reason = f"failed to compile site query ({e}); using built-in only"
            builtin = os.path.join(QUERY_DIR, f"{self.language}.scm")
            if os.path.exists(builtin):
                try:
                    self._scm = open(builtin, encoding="utf-8").read()
                    self._query = Query(lang, self._scm)
                    self.sources = [{"role": "builtin-fallback", "path": builtin}]
                    self.available = True
                except Exception as e2:                 # pragma: no cover
                    self._reason = f"built-in query also failed: {e2}"
            return
        self.available = True

    @property
    def reason(self):
        return self._reason

    def query_source_hash(self) -> str | None:
        """Content hash of the .scm file, so an evidence bundle can record
        exactly which version of the detection rules produced a finding."""
        if not hasattr(self, "_scm"):
            return None
        import hashlib
        return hashlib.sha256(self._scm.encode()).hexdigest()[:16]

    def run(self, src: bytes):
        """Yield Match objects for a source buffer."""
        if not self.available:
            return
        tree = self._parser.parse(src)
        cursor = self._QueryCursor(self._query)
        for pattern_idx, caps in cursor.matches(tree.root_node):
            m = Match(pattern=pattern_idx)
            try:
                m.settings = dict(self._query.pattern_settings(pattern_idx) or {})
            except Exception:
                m.settings = {}
            anchor = None
            for name, nodes in caps.items():
                if not nodes:
                    continue
                node = nodes[0]
                m.caps[name] = src[node.start_byte:node.end_byte].decode("utf-8", "replace")
                m.nodes[name] = node
                if name in ("site", "call") and anchor is None:
                    anchor = node
            if anchor is None:
                # fall back to any captured node for the line number
                anchor = next(iter(m.nodes.values()), None)
            m.line = (anchor.start_point[0] + 1) if anchor is not None else 0
            yield m

    def describe_sources(self) -> list[dict]:
        """Provenance of every .scm merged into this engine (role + path),
        so a scan can record which detection rules — built-in and site — ran."""
        return list(self.sources)


# --- per-run engine cache ---------------------------------------------------
# Collectors hold a module-level engine for the default (import-time) query
# resolution. When a scan supplies an explicit query_dir, get_engine returns a
# cached engine bound to that directory so site overrides take effect without
# rebuilding on every file.
_ENGINE_CACHE: dict = {}


def get_engine(language: str, query_dir: str | None = None) -> "QueryEngine":
    key = (language, query_dir or os.environ.get("QRAMP_QUERY_DIR")
           or _discover_project_query_dir())
    eng = _ENGINE_CACHE.get(key)
    if eng is None:
        eng = QueryEngine(language, query_dir=query_dir)
        _ENGINE_CACHE[key] = eng
    return eng
