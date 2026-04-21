"""Memory profiling test for configuration validation and creation."""

import pytest
from wrknv.memray.runner import run_memray_stress


@pytest.mark.memray
def test_config_validation_memory(memray_output_dir, memray_baseline, memray_baselines_path):
    """Profile memory allocations in config validation hot path."""
    run_memray_stress(
        script="scripts/memray/memray_config_stress.py",
        baseline_key="config_total_allocations",
        output_dir=memray_output_dir,
        baselines=memray_baseline,
        baselines_path=memray_baselines_path,
    )
