#!/usr/bin/env bash
# Audit what this project depends on, and nothing else.
#
# The scanners used to be installed into the same virtualenv they then audited:
#
#     uv venv
#     uv pip install bandit safety pip-audit
#     source .venv/bin/activate
#     pip-audit || true
#
# So an advisory against a scanner's own dependency was reported as this
# project's. It went unnoticed here only because the audit could not fail --
# `|| true` swallowed the exit status, which also meant a real advisory against
# a real dependency was equally invisible.
#
# Instead the audit reads the resolved lock, and pip-audit runs from `uvx`,
# which puts it in its own environment where its dependencies are nobody's
# problem. That is what makes it safe to let the exit status through.
set -euo pipefail

# A full template rather than `mktemp -t <prefix>`: GNU mktemp requires a
# template ending in at least three X's, where BSD mktemp takes the argument as
# a bare prefix -- so the short form runs on macOS and fails on the runner.
REQUIREMENTS="$(mktemp "${TMPDIR:-/tmp}/rpcplugin-audit-requirements.XXXXXX")"
trap 'rm -f "${REQUIREMENTS}"' EXIT

# Everything the lock resolves, dev groups included: a vulnerable test-time
# dependency is still worth knowing about. Workspace members are left out --
# they are this project, not something it depends on, and they are not on PyPI
# for pip-audit to look up.
uv export --no-emit-workspace --format requirements-txt > "${REQUIREMENTS}"
echo "==> auditing $(grep -c '==' "${REQUIREMENTS}") locked packages"

# The export is fully pinned, so there is nothing to resolve. `--no-deps` says
# so, and `--disable-pip` keeps pip-audit from building a throwaway virtualenv
# to resolve with -- which it does even for a pinned file, and which fails on a
# host whose ensurepip cannot run.
uvx pip-audit --desc --no-deps --disable-pip --requirement "${REQUIREMENTS}"
