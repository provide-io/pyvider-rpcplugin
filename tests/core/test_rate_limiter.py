import pytest
import asyncio
from unittest.mock import patch # Required for mocker if not already globally available through pytest

from pyvider.rpcplugin.rate_limiter import TokenBucketRateLimiter
from pyvider.telemetry import logger # For logger access if needed by caplog or direct patching

# Disable all logging for this test module to avoid polluting test output,
# unless specific log tests are being done with caplog.
# This can be done with pytest.ini or fixtures if preferred globally.
# For now, individual tests will manage log assertions if needed.

def test_rate_limiter_init_invalid_capacity():
    with pytest.raises(ValueError, match="Capacity must be positive."):
        TokenBucketRateLimiter(capacity=0, refill_rate=1)
    with pytest.raises(ValueError, match="Capacity must be positive."):
        TokenBucketRateLimiter(capacity=-1, refill_rate=1)

def test_rate_limiter_init_invalid_refill_rate():
    with pytest.raises(ValueError, match="Refill rate must be positive."):
        TokenBucketRateLimiter(capacity=1, refill_rate=0)
    with pytest.raises(ValueError, match="Refill rate must be positive."):
        TokenBucketRateLimiter(capacity=1, refill_rate=-1)

@pytest.mark.asyncio
async def test_rate_limiter_denies_when_empty(mocker): # Removed caplog
    # Patch time.monotonic to control time precisely
    mock_time = mocker.patch("time.monotonic")
    mock_logger_warning = mocker.patch("pyvider.rpcplugin.rate_limiter.logger.warning") # Patch logger

    # Initial time
    mock_time.return_value = 1000.0
    limiter = TokenBucketRateLimiter(capacity=1, refill_rate=10) # 1 token capacity, high refill

    # Consume the first token
    mock_time.return_value = 1000.001 # Minimal time advance, effectively no refill
    assert await limiter.is_allowed() # Should consume the token, tokens approx 0

    # Try to consume another immediately - should be denied
    mock_time.return_value = 1000.002 # Minimal time advance again
    assert not await limiter.is_allowed() # Should be denied

    # Check for the warning log
    found_log = False
    for call_args_tuple in mock_logger_warning.call_args_list:
        args, _ = call_args_tuple
        if args and "Request denied. No tokens available." in args[0]:
            found_log = True
            break
    assert found_log, f"Expected 'Request denied' log not found. Logs: {mock_logger_warning.call_args_list}"

@pytest.mark.asyncio
async def test_get_current_tokens(mocker):
    mock_time = mocker.patch("time.monotonic")
    mock_time.return_value = 1000.0
    limiter = TokenBucketRateLimiter(capacity=5, refill_rate=1)
    assert await limiter.get_current_tokens() == 5.0 # Initial capacity

    mock_time.return_value = 1000.1 # Advance time slightly
    await limiter.is_allowed() # Consume one, tokens become ~4 + tiny refill

    # get_current_tokens doesn't refill by default in the current implementation.
    # If it did, the expected value would be different.
    # Current tokens = 5 (initial) - 1 (consumed) = 4. Refill is not counted by get_current_tokens.
    # The internal _tokens value right after consumption is 4.0
    assert await limiter.get_current_tokens() == 4.0

@pytest.mark.asyncio
async def test_rate_limiter_refills_over_time(mocker):
    mock_time = mocker.patch("time.monotonic")

    mock_time.return_value = 1000.0
    limiter = TokenBucketRateLimiter(capacity=2, refill_rate=1) # 2 tokens, 1 token/sec

    # Consume all tokens
    assert await limiter.is_allowed() # Token 1, remaining ~1
    mock_time.return_value = 1000.01 # Negligible time passes
    assert await limiter.is_allowed() # Token 2, remaining ~0

    mock_time.return_value = 1000.02
    assert not await limiter.is_allowed() # Denied

    # Wait for 1 second (simulated) - should add 1 token
    mock_time.return_value = 1001.02
    assert await limiter.is_allowed() # Allowed, 1 token refilled

    mock_time.return_value = 1001.03
    assert not await limiter.is_allowed() # Denied again

    # Wait for 2 more seconds (simulated) - should add 2 tokens, cap at 2
    mock_time.return_value = 1003.03
    assert await limiter.is_allowed() # Allowed
    mock_time.return_value = 1003.04
    assert await limiter.is_allowed() # Allowed
    mock_time.return_value = 1003.05
    assert not await limiter.is_allowed() # Denied, bucket empty again

    current_tokens_after_all = await limiter.get_current_tokens()
    # After last denial, tokens should be < 1
    assert current_tokens_after_all < 1.0

@pytest.mark.asyncio
async def test_refill_does_not_exceed_capacity(mocker):
    mock_time = mocker.patch("time.monotonic")

    mock_time.return_value = 1000.0
    limiter = TokenBucketRateLimiter(capacity=5, refill_rate=100) # High refill rate

    # Tokens start at capacity (5)
    assert await limiter.get_current_tokens() == 5.0

    # Let a long time pass, tokens should not exceed capacity
    mock_time.return_value = 1100.0 # 100 seconds pass
    # Manually call _refill_tokens (as it's called by is_allowed)
    # To test _refill_tokens directly, we need to acquire the lock or make it public for test
    # For now, let's test through is_allowed or get_current_tokens if it refills.
    # The current get_current_tokens does NOT refill.
    # So, to check refill, we need to call is_allowed or simulate its internal lock + refill.

    # Consume one token to trigger refill logic within is_allowed
    await limiter.is_allowed()
    # After consumption and refill due to 100s passing, tokens should be capacity - 1
    # (5 initial - 1 consumed + min(capacity, 0 + 100s * 100 token/s) ) -> 5 - 1 = 4
    # No, it should be: capacity (after refill) - 1 consumed = 5 - 1 = 4
    assert await limiter.get_current_tokens() == 4.0

    # Let's verify _refill_tokens more directly by accessing internal state (not ideal but for 100%)
    mock_time.return_value = 1000.0
    limiter_direct = TokenBucketRateLimiter(capacity=5, refill_rate=100)
    limiter_direct._tokens = 0 # Start with empty bucket for this check
    limiter_direct._last_refill_timestamp = 1000.0

    mock_time.return_value = 1100.0 # 100 seconds pass
    async with limiter_direct._lock: # Acquire lock like is_allowed does
        await limiter_direct._refill_tokens()
    assert await limiter_direct.get_current_tokens() == 5.0 # Should be capped at 5

@pytest.mark.asyncio
async def test_refill_no_time_passed(mocker):
    mock_time = mocker.patch("time.monotonic", return_value=1000.0)
    limiter = TokenBucketRateLimiter(capacity=5, refill_rate=1)

    initial_tokens = await limiter.get_current_tokens()

    # Call _refill_tokens (indirectly, or directly if made testable) when no time has passed
    # We can test this by calling is_allowed multiple times with no time change
    await limiter.is_allowed() # Consumes 1, tokens become 4
    # time is still 1000.0
    tokens_before_second_check = await limiter.get_current_tokens() # is 4

    # This call to is_allowed will call _refill_tokens, but elapsed_time will be 0
    await limiter.is_allowed() # Consumes 1, tokens become 3

    # Assert that tokens only decreased by 1, meaning no refill happened
    assert await limiter.get_current_tokens() == 3.0
    assert tokens_before_second_check - await limiter.get_current_tokens() == 1.0

# Note: The main() function and if __name__ == "__main__": block in
# rate_limiter.py are not typically unit tested and can be excluded
# from coverage with # pragma: no cover if 100% on the class is the goal.
# For this exercise, I'm focusing on the class TokenBucketRateLimiter.

# 🐍🏗️🔌
