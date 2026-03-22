"""Memory profiling test for transport creation and validation."""

import pytest
from wrknv.memray.runner import run_memray_stress


@pytest.mark.memray
def test_transport_creation_memory(memray_output_dir, memray_baseline, memray_baselines_path):
    """Profile memory allocations in transport creation hot path."""
    run_memray_stress(
        script="scripts/memray/memray_transport_stress.py",
        baseline_key="transport_total_allocations",
        output_dir=memray_output_dir,
        baselines=memray_baseline,
        baselines_path=memray_baselines_path,
    )
