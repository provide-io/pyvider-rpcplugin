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
from typing import Any  # Added Optional

# Ensure sources are importable by example scripts
project_root = Path(__file__).resolve().parent.parent
src_path = project_root / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))
if str(project_root) not in sys.path:  # For `from examples.demo...`
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
    magic_cookie_value: str | None = None,
    # This key is what the server part of the example script will look for in os.environ
    # It should match what example_utils.configure_for_example sets as PLUGIN_MAGIC_COOKIE_KEY
    # which is example_utils.DEFAULT_MAGIC_COOKIE_KEY ("PYVIDER_PLUGIN_MAGIC_COOKIE")
    magic_cookie_env_var_name: str = "PYVIDER_PLUGIN_MAGIC_COOKIE",
) -> tuple[bool, str, str, int]:
    """Runs a script and returns its success status, stdout, stderr, and exit code."""
    if args is None:
        args = []
    # Default CWD to project_root if not specified, as most examples expect this
    effective_cwd: Path = cwd if cwd is not None else project_root

    command = [sys.executable, str(script_path)] + args
    process = None

    # Prepare environment for the subprocess
    env = os.environ.copy()
    if magic_cookie_value:
        # This sets the environment variable that the server (running within the script)
        # will check via os.getenv(CONFIGURED_MAGIC_COOKIE_KEY).
        # The CONFIGURED_MAGIC_COOKIE_KEY is typically "PYVIDER_PLUGIN_MAGIC_COOKIE"
        # as set by example_utils.configure_for_example.
        env[magic_cookie_env_var_name] = magic_cookie_value

        # This makes PLUGIN_MAGIC_COOKIE_VALUE available for the script's initial config load,
        # before configure_for_example() might override it with a more specific value.
        # The value set here should be the one the server ultimately expects.
        env["PLUGIN_MAGIC_COOKIE_VALUE"] = magic_cookie_value
        # Also, ensure PLUGIN_MAGIC_COOKIE_KEY is set in env if the script relies on it being in env
        # for its own configure_for_example() to pick up.
        # example_utils.DEFAULT_MAGIC_COOKIE_KEY is "PYVIDER_PLUGIN_MAGIC_COOKIE"
        env["PLUGIN_MAGIC_COOKIE_KEY"] = magic_cookie_env_var_name

        print(
            f"    Setting env {magic_cookie_env_var_name}={magic_cookie_value}, "
            f"PLUGIN_MAGIC_COOKIE_KEY={magic_cookie_env_var_name}, "
            f"and PLUGIN_MAGIC_COOKIE_VALUE={magic_cookie_value} for {script_path.name}"
        )

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(
                effective_cwd
            ),  # Run script from its own directory or specified CWD
            env=env,  # Pass the modified environment
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(), timeout=timeout
        )
        stdout = stdout_bytes.decode().strip()
        stderr = stderr_bytes.decode().strip()
        raw_exit_code = process.returncode

        # Ensure exit_code is always an int
        exit_code: int = raw_exit_code if raw_exit_code is not None else -1

        success = False
        if expected_to_fail:
            if exit_code != 0:
                if expected_stderr_contains and expected_stderr_contains in stderr:
                    success = True
                elif not expected_stderr_contains:  # Any non-zero exit is fine
                    success = True
            else:  # Expected to fail but didn't
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

    # List of examples to run. Each entry is a dictionary.
    # Keys: "file" (str), "args" (List[str]), "exp_fail" (bool),
    #       "exp_stderr" (Optional[str]), "cookie" (Optional[str])
    # Note: Paths for commands inside scripts (like to 00_dummy_server.py) assume examples_dir is CWD or in PYTHONPATH.

    scripts_to_run: list[dict[str, Any]] = [
        {
            "file": "00_dummy_server.py",
            "args": ["--help"],
            "exp_fail": False,
            "exp_stderr": None,
            "cookie": None,
        },
        {
            "file": "01_quick_start.py",
            "args": [],
            "exp_fail": False,
            "exp_stderr": None,
            "cookie": None,
        },  # Starts dummy_server itself
        {
            "file": "02_server_setup.py",
            "args": [],
            "exp_fail": False,
            "exp_stderr": None,
            "cookie": "example-unix-cookie",
        },
        {
            "file": "03_client_connection.py",
            "args": [],
            "exp_fail": False,
            "exp_stderr": None,
            "cookie": "client-conn-cookie",
        },
        {
            "file": "04_transport_options.py",
            "args": [],
            "exp_fail": False,
            "exp_stderr": None,
            "cookie": "unix-benchmark-cookie",
        },
        # 05_security_mtls.py requires cert generation, skip for now
        {
            "file": "06_async_patterns.py",
            "args": [],
            "exp_fail": False,
            "exp_stderr": None,
            "cookie": "async-patterns-cookie",
        },
        {
            "file": "07_error_handling.py",
            "args": [],
            "exp_fail": False,
            "exp_stderr": None,
            "cookie": "error-handling-cookie",
        },  # This script simulates errors but should exit 0
        {
            "file": "08_production_config.py",
            "args": [],
            "exp_fail": False,
            "exp_stderr": None,
            "cookie": "production-server-2024",
        },
        {
            "file": "09_custom_protocols.py",
            "args": [],
            "exp_fail": False,
            "exp_stderr": None,
            "cookie": "custom-stream-cookie",
        },
        {
            "file": "10_performance_tuning.py",
            "args": [],
            "exp_fail": False,
            "exp_stderr": None,
            "cookie": "perf-tuning-cookie",
        },
        {
            "file": "11_end_to_end.py",
            "args": [],
            "exp_fail": False,
            "exp_stderr": None,
            "cookie": "e2e-test-cookie",
        },
        {
            "file": str(Path("demo") / "echo_client.py"),
            "args": [],
            "exp_fail": False,
            "exp_stderr": None,
            "cookie": None,
        },  # Starts its own server
        {
            "file": str(Path("kvproto") / "py_rpc" / "py_kv_client.py"),
            "args": ["put", "testkey", "testvalue"],
            "exp_fail": False,
            "exp_stderr": None,
            "cookie": None,
        },  # Starts its own server
        {
            "file": str(Path("kvproto") / "py_rpc" / "py_kv_client.py"),
            "args": ["get", "testkey"],
            "exp_fail": False,
            "exp_stderr": None,
            "cookie": None,
        },  # Starts its own server
    ]

    print_section("Running All Examples")

    for script_info in scripts_to_run:
        script_file = script_info["file"]
        script_args = script_info["args"]
        exp_fail = script_info["exp_fail"]
        exp_stderr = script_info["exp_stderr"]
        cookie_val = script_info["cookie"]

        script_path = examples_dir / script_file
        print(f"\n⏳ Running: {script_path.name} {' '.join(script_args)}...")

        # Most examples assume they are run from project root or `examples/`
        # and `src` is in path. Our `sys.path` setup at top of this script handles `src`.
        # For imports like `from examples.demo...`, project root needs to be in path.
        # CWD for subprocess can be examples_dir.
        success, stdout, stderr, exit_code = await run_script(
            script_path,
            args=script_args,
            cwd=project_root,  # Run from project root so "examples.demo" imports work
            expected_to_fail=exp_fail,
            expected_stderr_contains=exp_stderr,
            magic_cookie_value=cookie_val,
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
