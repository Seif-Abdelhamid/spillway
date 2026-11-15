"""Map Terraform resource addresses back to `file:line` in .tf sources, for SARIF annotations."""

from __future__ import annotations

import os
import re

from spillway.loader import strip_index

MAX_TF_FILES = 2000
MAX_TF_BYTES = 2 * 1024 * 1024
_RESOURCE = re.compile(r'^\s*resource\s+"([A-Za-z0-9_-]+)"\s+"([A-Za-z0-9_-]+)"', re.MULTILINE)


def index_sources(tf_dir: str) -> dict[str, tuple[str, int]]:
    """Root-module resources only; module addresses are left without a physical location."""
    found: dict[str, tuple[str, int]] = {}
    root = os.path.realpath(tf_dir)
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        if dirpath != root:
            continue  # child directories are modules, which have their own addresses
        for fname in sorted(filenames):
            if not fname.endswith(".tf"):
                continue
            count += 1
            if count > MAX_TF_FILES:
                return found
            path = os.path.join(dirpath, fname)
            if os.path.islink(path) or os.path.getsize(path) > MAX_TF_BYTES:
                continue
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            for m in _RESOURCE.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                rel = os.path.relpath(path, root).replace(os.sep, "/")
                found.setdefault(f"{m.group(1)}.{m.group(2)}", (rel, line))
    return found


def locate(address: str, index: dict[str, tuple[str, int]]) -> tuple[str, int] | None:
    return index.get(strip_index(address))
