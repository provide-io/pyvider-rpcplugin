#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""A script to enforce header and footer conformance on Python files."""

import ast
from pathlib import Path
import sys

# The exact footer to be used

# The placeholder docstring for modules without one
PLACEHOLDER_DOCSTRING = '"""TODO: Add module docstring."""'

def get_module_docstring(source: str) -> str | None:
    """
    Safely extracts the module-level docstring from Python source code.

    Args:
        source: The source code as a string.

    Returns:
        The docstring if found, otherwise None.
    """
    try:
        tree = ast.parse(source)
        return ast.get_docstring(tree)
    except (SyntaxError, ValueError):
        # Handle cases with invalid Python syntax or other parsing issues gracefully
        return None

def conform_file(file_path: str | Path) -> None:
    """
    Applies the header and footer protocol to a single Python file.

    Args:
        file_path: The path to the Python file to conform.
    """
    try:
        file_path = Path(file_path)
        if not file_path.is_file():
            print(f"Skipping non-existent file: {file_path}", file=sys.stderr)
            return

        original_content = file_path.read_text(encoding="utf-8")
        lines = original_content.splitlines()

        # Determine if the file is an executable
        is_executable = lines and lines[0].startswith("#!")

        # Preserve the module docstring
        docstring = get_module_docstring(original_content)
        if docstring:
            # Format the docstring with triple quotes and preserve internal newlines
            docstring = f'"""{docstring}"""'
        else:
            docstring = PLACEHOLDER_DOCSTRING

        # Strip existing headers and footers to start fresh
        # Find the start of the code body (first non-comment, non-docstring line)
        body_start_index = 0
        in_docstring = False
        for i, line in enumerate(lines):
            if line.strip().startswith('"""') or line.strip().startswith("'''"):
                if not in_docstring:
                    in_docstring = True
                else:
                    in_docstring = False
                if i > body_start_index:
                    body_start_index = i + 1
                continue

            if not in_docstring and line.strip() and not line.strip().startswith("#"):
                body_start_index = i
                break

        # If the file is only comments and docstrings, handle it
        if body_start_index == 0 and all(line.strip().startswith("#") or not line.strip() for line in lines if '"""' not in line and "'''" not in line):
             body_start_index = len(lines)

        body_lines = lines[body_start_index:]
        body = "\n".join(body_lines).strip()

        # Remove old footers

        # Construct the new header
        header_lines = []
        if is_executable:
            header_lines.append("#!/usr/bin/env python3")
        else:
            header_lines.append("# ")

        header_lines.extend([
            "# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.",
            "# SPDX-License-Identifier: Apache-2.0",
            "#",
            "",
        ])
        header = "\n".join(header_lines)

        # Assemble the new content
        new_content = f"{header}{docstring}\n\n{body}\n\n{FOOTER}\n"

        # Overwrite the file with the new content
        file_path.write_text(new_content, encoding="utf-8")
        print(f"Conformed: {file_path}")

    except Exception as e:
        print(f"Error processing file {file_path}: {e}", file=sys.stderr)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 conform.py <file1.py> <file2.py> ...", file=sys.stderr)
        sys.exit(1)

    for file_path in sys.argv[1:]:
        conform_file(file_path)

# 🔌📞🔚
