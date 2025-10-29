#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
"""A script to update the headers and footers of all python files."""

import os
import re

# This pattern is more robust. It looks for the start of a file (or start of a line after a shebang),
# followed by optional comments/whitespace, and then captures the first triple-quoted string.
DOCSTRING_RE = re.compile(
    r"^(?:#!.*\n)?(?:(?:#.*\n|\s*\n)*)(\"\"\"(?:.|\n)*?\"\"\")", re.MULTILINE
)

def update_file_content(file_path: str) -> None:
    """Read, update, and write the content of a single Python file."""
    if file_path.endswith(("_pb2.py", "_pb2_grpc.py")):
        print(f"Skipping generated file: {file_path}")
        return

    try:
        with open(file_path, encoding="utf-8") as f:
            original_content = f.read()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return

    content = original_content

    # Determine the first line and strip shebang if present
    is_executable = content.startswith("#!")
    first_line = "#!/usr/bin/env python3" if is_executable else "# "
    if is_executable:
        lines = content.splitlines()
        content = "\n".join(lines[1:])

    # Find and extract the module docstring
    docstring_match = DOCSTRING_RE.search(content)
    if docstring_match:
        docstring = docstring_match.group(1)
        # Remove the docstring and any preceding comments/whitespace from the main content
        content = content[docstring_match.end() :].lstrip()
    else:
        docstring = '"""TODO: Add module docstring."""'
        # If no docstring, just strip leading comments and whitespace
        # to get to the code.
        lines = content.splitlines()
        code_start_index = 0
        for i, line in enumerate(lines):
            stripped_line = line.strip()
            if stripped_line and not stripped_line.startswith("#"):
                code_start_index = i
                break
        content = "\n".join(lines[code_start_index:])

    # Clean up the main body of the code
    # Remove old footers and any trailing whitespace
    lines = content.splitlines()
    cleaned_lines = []
    for line in lines:
        stripped_line = line.strip()
        if not (
            stripped_line.startswith("# 📞")
            or stripped_line.startswith("# 🐍")
            or stripped_line.startswith("### 🐍")
        ):
            cleaned_lines.append(line)
    content = "\n".join(cleaned_lines).rstrip()

    # Construct the final file content
    spdx_block = (
        "# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.\n"
        "# SPDX-License-Identifier: Apache-2.0\n"
        "#"
    )

    final_content = (
        f"{first_line}\n"
        f"{spdx_block}\n\n"
        f"{docstring}\n\n"
        f"{content}\n\n"
        f"# 📞🔌🔚\n"
    )

    # Write the new content back to the file
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(final_content)
        print(f"Updated: {file_path}")
    except Exception as e:
        print(f"Error writing to {file_path}: {e}")


def main() -> None:
    """Find and update all Python files in the specified directories."""
    search_dirs = ["src", "examples", "docs", "tests"]
    for directory in search_dirs:
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".py"):
                    update_file_content(os.path.join(root, file))


if __name__ == "__main__":
    main()
