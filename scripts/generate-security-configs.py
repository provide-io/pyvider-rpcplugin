#!/usr/bin/env python3
"""Generate tool-specific secret scanning configs from a single source file.

Reads .secret-scan-allowlist.yaml and generates:
- .trufflehog-exclude-paths.txt
- .gitguardian.yaml
- .gitleaks.toml

Usage:
    python scripts/generate-security-configs.py
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml


def glob_to_regex(pattern: str) -> str:
    """Convert glob pattern to regex pattern."""
    # Escape regex special chars except * and ?
    result = re.escape(pattern)
    # Convert glob wildcards to regex
    result = result.replace(r"\*\*", ".*")  # ** matches anything including /
    result = result.replace(r"\*", "[^/]*")  # * matches anything except /
    result = result.replace(r"\?", ".")  # ? matches single char
    return f"{result}$"


def generate_trufflehog(paths: list[str], description: str) -> str:
    """Generate .trufflehog-exclude-paths.txt content."""
    lines = [
        "# TruffleHog path exclusions",
        f"# {description}",
        "# Auto-generated from .secret-scan-allowlist.yaml",
        "",
    ]
    for path in paths:
        lines.append(glob_to_regex(path))
    return "\n".join(lines) + "\n"


def generate_gitguardian(paths: list[str], description: str) -> str:
    """Generate .gitguardian.yaml content."""
    config = {
        "version": 2,
        "secret": {
            "ignored_paths": paths,
        },
    }
    header = f"""\
# GitGuardian configuration
# {description}
# Auto-generated from .secret-scan-allowlist.yaml
# https://docs.gitguardian.com/ggshield-docs/configuration

"""
    return header + yaml.dump(config, default_flow_style=False, sort_keys=False)


def generate_gitleaks(paths: list[str], description: str) -> str:
    """Generate .gitleaks.toml content."""
    lines = [
        "# Gitleaks configuration",
        f"# {description}",
        "# Auto-generated from .secret-scan-allowlist.yaml",
        "# https://github.com/gitleaks/gitleaks",
        "",
        "[extend]",
        "useDefault = true",
        "",
        "[[allowlists]]",
        f'description = "{description}"',
        "paths = [",
    ]
    for path in paths:
        regex = glob_to_regex(path)
        lines.append(f"    '''{regex}''',")
    lines.append("]")
    return "\n".join(lines) + "\n"


def main() -> None:
    """Generate all security config files."""
    repo_root = Path(__file__).parent.parent
    source_file = repo_root / ".secret-scan-allowlist.yaml"

    if not source_file.exists():
        print(f"Error: {source_file} not found")
        return

    with open(source_file) as f:
        config = yaml.safe_load(f)

    paths = config.get("paths", [])
    description = config.get("description", "Allowlisted paths")

    # Generate each config file
    configs = [
        (".trufflehog-exclude-paths.txt", generate_trufflehog(paths, description)),
        (".gitguardian.yaml", generate_gitguardian(paths, description)),
        (".gitleaks.toml", generate_gitleaks(paths, description)),
    ]

    for filename, content in configs:
        filepath = repo_root / filename
        with open(filepath, "w") as f:
            f.write(content)
        print(f"Generated {filepath}")


if __name__ == "__main__":
    main()
