"""Memory profiling test for protocol service object lifecycle."""

import pytest
from wrknv.memray.runner import run_memray_stress


@pytest.mark.memray
def test_protocol_service_memory(memray_output_dir, memray_baseline, memray_baselines_path):
    """Profile memory allocations in protocol service lifecycle."""
    run_memray_stress(
        script="scripts/memray/memray_protocol_stress.py",
        baseline_key="protocol_total_allocations",
        output_dir=memray_output_dir,
        baselines=memray_baseline,
        baselines_path=memray_baselines_path,
    )
