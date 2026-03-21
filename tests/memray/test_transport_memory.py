"""Memory profiling test for transport creation and validation."""

import pytest

from tests.memray.conftest import assert_allocation_within_threshold, run_memray_stress


@pytest.mark.memray
def test_transport_creation_memory(memray_output_dir, memray_baseline):
    """Profile memory allocations in transport creation hot path."""
    bin_path, total_allocs = run_memray_stress("memray_transport_stress", memray_output_dir)

    assert bin_path.exists(), f"memray binary not created: {bin_path}"
    assert total_allocs > 0, "No allocations recorded"

    baseline = memray_baseline.get("transport_total_allocations")
    assert_allocation_within_threshold(baseline, total_allocs, "transport")
