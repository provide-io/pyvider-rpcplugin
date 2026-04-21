#!/usr/bin/env python
"""Memray analysis utilities for pyvider-rpcplugin.

Provides post-run analysis for memray stress test binaries:
- Parse .bin files and extract allocation statistics
- Generate flamegraph HTML visualizations
- Generate ANALYSIS.md report with comparisons
"""

from pathlib import Path
import subprocess  # nosec
import sys
from typing import Any


def parse_memray_stats(binfile: Path) -> dict[str, Any]:
    """Parse memray stats output from a binary file."""
    try:
        result = subprocess.run(
            ["memray", "stats", str(binfile)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return {"error": f"memray stats failed: {result.stderr}"}

        stats: dict[str, Any] = {"output": result.stdout}
        lines = result.stdout.split("\n")
        for i, line in enumerate(lines):
            if "peak memory" in line.lower() and i + 1 < len(lines):
                stats["peak_memory_line"] = lines[i + 1].strip()
            if "total allocations" in line.lower() and i + 1 < len(lines):
                stats["total_allocations_line"] = lines[i + 1].strip()
            if "total memory allocated" in line.lower() and i + 1 < len(lines):
                stats["total_memory_line"] = lines[i + 1].strip()
        return stats
    except subprocess.TimeoutExpired:
        return {"error": "memray stats timed out"}
    except Exception as e:
        return {"error": str(e)}


def generate_flamegraph(binfile: Path, output_html: Path | None = None) -> bool:
    """Generate flamegraph HTML from memray binary file."""
    try:
        if output_html is None:
            output_html = binfile.parent / f"{binfile.stem}_flamegraph.html"

        result = subprocess.run(
            ["memray", "flamegraph", "--force", str(binfile), "-o", str(output_html)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            print(f"  Generated: {output_html.name}")
            return True
        else:
            print(f"  Failed: {result.stderr[:200]}")
            return False
    except subprocess.TimeoutExpired:
        print("  Flamegraph generation timed out")
        return False
    except Exception as e:
        print(f"  Error: {e}")
        return False


def generate_analysis_report(output_dir: Path) -> str:
    """Generate comprehensive analysis report from all stress test binaries."""
    binfiles = sorted(output_dir.glob("memray_*.bin"))

    if not binfiles:
        return "No memray binary files found in output directory."

    report_lines = [
        "# Memray Analysis Report — pyvider-rpcplugin",
        "",
        f"Output directory: `{output_dir}`",
        "",
        "## Summary",
        "",
        "| Test | File Size | Peak Memory | Total Allocations |",
        "| ---- | --------- | ----------- | ----------------- |",
    ]

    for binfile in binfiles:
        name = binfile.stem
        stats = parse_memray_stats(binfile)
        size = f"{binfile.stat().st_size:,} bytes"
        peak = stats.get("peak_memory_line", "N/A")
        allocs = stats.get("total_allocations_line", "N/A")
        if "error" in stats:
            report_lines.append(f"| {name} | {size} | ERROR | {stats['error']} |")
        else:
            report_lines.append(f"| {name} | {size} | {peak} | {allocs} |")

    report_lines.extend(
        [
            "",
            "## Hot Paths Profiled",
            "",
            "1. **Handshake parsing** (`memray_handshake_stress`): parse_handshake_response, validate_magic_cookie, cert processing",
            "2. **Transport creation** (`memray_transport_stress`): TCPSocketTransport/UnixSocketTransport instantiation, endpoint validation",
            "3. **Rate limiter** (`memray_rate_limiter_stress`): RateLimitingInterceptor.intercept_service token bucket checks",
            "4. **Protocol services** (`memray_protocol_stress`): SubchannelConnection lifecycle, broker dict management",
            "5. **Config validation** (`memray_config_stress`): validate_protocol_versions_list, validate_transport_list, HandshakeConfig creation",
            "",
            "## Next Steps",
            "",
            "```bash",
            "# View flamegraphs in browser",
            "open memray-output/*_flamegraph.html",
            "",
            "# Update baselines after optimization",
            "we run memray.update-baseline",
            "```",
            "",
        ]
    )

    return "\n".join(report_lines)


def main() -> None:
    """Run analysis on all memray binaries in output directory."""
    output_dir = Path("memray-output")
    flamegraph_only = "--flamegraph-only" in sys.argv

    if not output_dir.exists():
        print("memray-output directory not found. Run: we run memray")
        return

    print("Analyzing memray results...")
    print()

    # Generate flamegraphs
    for binfile in sorted(output_dir.glob("memray_*.bin")):
        print(f"Processing {binfile.name}...")
        generate_flamegraph(binfile)

    if flamegraph_only:
        print("\nFlamegraph generation complete.")
        return

    # Generate report
    report = generate_analysis_report(output_dir)
    report_file = output_dir / "ANALYSIS.md"
    report_file.write_text(report)

    print()
    print(f"Analysis report: {report_file}")
    print()
    print(report)


if __name__ == "__main__":
    main()
