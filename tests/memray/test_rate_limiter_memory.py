"""Memory profiling test for rate limiting interceptor."""

import pytest
from wrknv.memray.runner import run_memray_stress


@pytest.mark.memray
def test_rate_limiter_memory(memray_output_dir, memray_baseline, memray_baselines_path):
    """Profile memory allocations in rate limiter intercept hot path."""
    run_memray_stress(
        script="scripts/memray/memray_rate_limiter_stress.py",
        baseline_key="rate_limiter_total_allocations",
        output_dir=memray_output_dir,
        baselines=memray_baseline,
        baselines_path=memray_baselines_path,
    )
