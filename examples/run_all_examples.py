#!/usr/bin/env python3
# examples/run_all_examples.py
"""
Runs all relevant Python example scripts and checks for unexpected failures.
"""

import asyncio
import os
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any

# Ensure sources are importable by example scripts
project_root = Path(__file__).resolve().parent.parent
src_path = project_root / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))


# Configure logger for this script
# (Using print for simplicity in this test runner for now)


def print_section(title: str) -> None:
    print("\n" + "=" * 70)
    print(f"📋 {title}")
    print("=" * 70)


def print_result(
    script_name: str, success: bool, stdout: str, stderr: str, exit_code: int
) -> None:
    status = "✅ PASSED" if success else "❌ FAILED"
    print(f"\n--- {script_name} --- {status} ---")
    if stdout:
        print("--- STDOUT ---")
        print(stdout.strip())
    if (
        stderr and not success
    ):  # Only print stderr if failed, or if specifically requested
        print("--- STDERR ---")
        print(stderr.strip())
    if not success:
        print(f"Exit Code: {exit_code}")
    print("." * 70)


async def run_script(
    script_path: Path,
    timeout: int = 30,
    args: list[str] | None = None,
    cwd: Path | None = None,
    expected_to_fail: bool = False,
    expected_stderr_contains: str | None = None,
) -> tuple[bool, str, str, int]:
    """Runs a script and returns its success status, stdout, stderr, and exit code."""
    if args is None:
        args = []
    effective_cwd: Path = cwd if cwd is not None else project_root

    command = [sys.executable, str(script_path)] + args
    process = None
    # Ensure env is always set up, even if not modified by cookies
    env = os.environ.copy()
    # Removed automatic magic cookie setup from here.
    # If a specific test needs a magic cookie, it should be passed via `env`
    # in the `script_info` dictionary for that test, or the example script
    # itself should handle default/test cookies if run standalone.

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(effective_cwd),
            env=env,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(), timeout=timeout
        )
        stdout = stdout_bytes.decode().strip()
        stderr = stderr_bytes.decode().strip()
        raw_exit_code = process.returncode
        exit_code: int = raw_exit_code if raw_exit_code is not None else -1

        success = False
        if expected_to_fail:
            if exit_code != 0:
                if expected_stderr_contains and expected_stderr_contains in stderr:
                    success = True
                elif not expected_stderr_contains:
                    success = True
            else:
                stderr += "\nERROR: Script was expected to fail but exited with 0."
        elif exit_code == 0:
            success = True

        return success, stdout, stderr, exit_code
    except TimeoutError:
        if process:
            process.terminate()
            await process.wait()
        return False, "", f"Timeout after {timeout}s", -1
    except Exception as e:
        return False, "", f"Execution error: {e}", -1


async def main() -> None:
    examples_dir = Path(__file__).resolve().parent
    overall_success = True
    results: list[tuple[str, bool, str, str, int]] = []

    scripts_to_run: list[dict[str, Any]] = [
        { # Was 00_dummy_server.py
            "file": "ch02_dummy_server.py", "args": ["--help"], "exp_fail": False,
            "exp_stderr": None,
        },
        { # Was 01_quick_start.py
            "file": "ch02_quick_start_client.py", "args": [], "exp_fail": False,
            "exp_stderr": None, # Launches ch02_dummy_server internally
        },
        { # Was 02_server_setup.py
            "file": "ch03_server_setup_concepts.py", "args": [], "exp_fail": False,
            "exp_stderr": None,
        },
        { # Was 04_transport_options.py
            "file": "ch04_transport_options_demo.py", "args": [], "exp_fail": False,
            "exp_stderr": None,
        },
        { # Was 03_client_connection.py
            "file": "ch06_client_setup_concepts.py", "args": [], "exp_fail": False,
            "exp_stderr": None,
        },
        { # Was new 07_echo_client.py
            "file": "ch07_echo_client.py", "args": [], "exp_fail": False,
            "exp_stderr": None, # Client manages server's cookie
        },
        # ch08_direct_client_connection.py (was 01b) is not run by this script.
        # ch09_security_mtls_example.py (was 05) is currently not run by this script.
        { # Was 06_async_patterns.py
            "file": "ch10_async_patterns_demo.py", "args": [], "exp_fail": False,
            "exp_stderr": None,
        },
        { # Was original 07_error_handling.py
            "file": "ch11_error_handling_demo.py", "args": [], "exp_fail": False,
            "exp_stderr": None,
        },
        { # Was 08_production_config.py
            "file": "ch12_production_config_discussion.py", "args": [], "exp_fail": False,
            "exp_stderr": None,
        },
        { # Was 09_custom_protocols.py
            "file": "ch13_custom_protocols_demo.py", "args": [], "exp_fail": False,
            "exp_stderr": None,
        },
        { # Was 10_performance_tuning.py
            "file": "ch14_performance_tuning_concepts.py", "args": [], "exp_fail": False,
            "exp_stderr": None,
        },
        { # Was new 11_e2e_client.py
            "file": "ch15_e2e_client.py", "args": [], "exp_fail": False,
            "exp_stderr": None, # Client manages server's cookie
        },
    ]

    print_section("Running All Examples")

    for script_info in scripts_to_run:
        script_file = script_info["file"]
        script_args = script_info.get("args", []) # Use .get for safety
        exp_fail = script_info.get("exp_fail", False)
        exp_stderr = script_info.get("exp_stderr")
        # cookie_val = script_info.get("cookie") # Removed cookie from general loop

        script_path = examples_dir / script_file
        if not script_path.exists():
            print(f"\nSKIPPING: {script_path.name} (File not found)")
            continue

        print(f"\n⏳ Running: {script_path.name} {' '.join(script_args)}...")

        success, stdout, stderr, exit_code = await run_script(
            script_path,
            args=script_args,
            cwd=project_root,
            expected_to_fail=exp_fail,
            expected_stderr_contains=exp_stderr,
            # magic_cookie_value is no longer passed here
        )
        results.append((script_path.name, success, stdout, stderr, exit_code))
        if not success:
            overall_success = False
        print_result(script_path.name, success, stdout, stderr, exit_code)

    print_section("Summary")
    all_passed_count = 0
    for name, success, _, _, _ in results:
        if success:
            all_passed_count += 1
        print(f"{'✅ PASSED' if success else '❌ FAILED'}: {name}")

    if overall_success:
        print(f"\n🎉 All {len(results)} executable examples passed!")
        sys.exit(0)
    else:
        failed_count = len(results) - all_passed_count
        print(f"\n❌ {failed_count} example(s) failed out of {len(results)}.")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
