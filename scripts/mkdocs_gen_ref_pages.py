#
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Generate the API reference pages for mkdocs."""

from __future__ import annotations

import os
from pathlib import Path

import mkdocs_gen_files

nav = mkdocs_gen_files.Nav()  # type: ignore[attr-defined,no-untyped-call]

# Get the directory containing mkdocs.yml (works in both standalone and monorepo)
config_dir = Path(os.getenv("MKDOCS_CONFIG_DIR", "."))
src_root = config_dir / "src"

# Fallback if source directory not found
if not src_root.exists():
    # Try current directory (for standalone builds)
    src_root = Path("src")
    if not src_root.exists():
        # No source files to document - exit silently
        import sys

        sys.exit(0)

for path in sorted(src_root.rglob("*.py")):
    if "__pycache__" in str(path):
        continue

    # Skip generated protobuf files
    if "pb2" in path.name:
        continue

    module_path = path.relative_to(src_root).with_suffix("")
    doc_path = Path("reference") / module_path.with_suffix(".md")
    full_doc_path = Path("reference") / module_path.with_suffix(".md")

    parts = tuple(module_path.parts)
    if any(part.startswith("_") and part != "__init__" for part in parts):
        continue

    if parts[-1] == "__init__":
        parts = parts[:-1]
        doc_path = doc_path.with_name("index.md")
        full_doc_path = full_doc_path.with_name("index.md")

    if not parts:
        continue

    # Strip "reference/" prefix from nav paths since SUMMARY.md is already in reference/
    nav_path = str(doc_path)
    if nav_path.startswith("reference/"):
        nav_path = nav_path[10:]  # Remove "reference/" prefix
    nav[parts] = nav_path

    with mkdocs_gen_files.open(full_doc_path, "w") as fd:
        identifier = ".".join(parts)
        print(f"::: {identifier}", file=fd)

    mkdocs_gen_files.set_edit_path(full_doc_path, path)

with mkdocs_gen_files.open("reference/SUMMARY.md", "w") as nav_file:
    nav_file.writelines(nav.build_literate_nav())

# 🔌📞🔚
