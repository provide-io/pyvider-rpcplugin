"""Memory profiling test for protocol service object lifecycle."""

import pytest

from tests.memray.conftest import assert_allocation_within_threshold, run_memray_stress


@pytest.mark.memray
def test_protocol_service_memory(memray_output_dir, memray_baseline):
    """Profile memory allocations in protocol service lifecycle."""
    bin_path, total_allocs = run_memray_stress("memray_protocol_stress", memray_output_dir)

    assert bin_path.exists(), f"memray binary not created: {bin_path}"
    assert total_allocs > 0, "No allocations recorded"

    baseline = memray_baseline.get("protocol_total_allocations")
    assert_allocation_within_threshold(baseline, total_allocs, "protocol")
