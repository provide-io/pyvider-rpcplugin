"""Memory profiling test for handshake parsing and validation."""

import pytest
from wrknv.memray.runner import run_memray_stress


@pytest.mark.memray
def test_handshake_parsing_memory(memray_output_dir, memray_baseline, memray_baselines_path):
    """Profile memory allocations in handshake parsing hot path."""
    run_memray_stress(
        script="scripts/memray/memray_handshake_stress.py",
        baseline_key="handshake_total_allocations",
        output_dir=memray_output_dir,
        baselines=memray_baseline,
        baselines_path=memray_baselines_path,
    )
