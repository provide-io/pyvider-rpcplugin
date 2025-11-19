#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""A script to enforce header and footer conformance on Python files."""

import re
import sys
from pathlib import Path

# The exact footer to be used
FOOTER = "# 📞🔌🔚"

# The placeholder docstring for modules without one
PLACEHOLDER_DOCSTRING = '"""TODO: Add module docstring."""'

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
        is_generated = "@generated" in original_content or "_pb2.py" in str(file_path)

        # Find the start of the code
        code_start_index = 0
        for i, line in enumerate(lines):
            if line.strip() and not line.strip().startswith("#"):
                code_start_index = i
                break

        # Check for module docstring
        has_docstring = False
        if code_start_index < len(lines):
            line = lines[code_start_index].lstrip()
            if line.startswith('"""') or line.startswith("'''"):
                has_docstring = True

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

        # Get the body of the code
        body_content = "\n".join(lines[code_start_index:])
        body_content = "\n".join(line for line in body_content.splitlines() if "🔚" not in line and "🐍" not in line and "🏗️" not in line).strip()


        # Add placeholder docstring if needed
        if not has_docstring and not is_generated:
            body_content = f"{PLACEHOLDER_DOCSTRING}\n\n{body_content}"


        # Assemble the new content
        new_content = f"{header}{body_content}\n\n{FOOTER}\n"


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
