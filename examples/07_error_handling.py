#!/usr/bin/env python3
# examples/07_error_handling.py
"""Demonstrates comprehensive error handling and recovery patterns with pyvider-rpcplugin."""

import asyncio
import random
import sys
import time
from pathlib import Path
from typing import Optional, List, Dict, Any

# Add src to path for examples
example_dir = Path(__file__).resolve().parent
project_root = example_dir.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from pyvider.rpcplugin import (  # noqa: E402
    plugin_server,
    plugin_client,
    create_basic_protocol,
    configure,
)
from pyvider.rpcplugin.exception import (  # noqa: E402
    RPCPluginError,
    TransportError,
    HandshakeError,
    ProtocolError,
    SecurityError,
)
from pyvider.telemetry import logger  # noqa: E402


class RobustServiceHandler:
    """Service handler demonstrating robust error handling patterns."""
    
    def __init__(self):
        self.request_count = 0
        self.error_count = 0
        self.recovery_count = 0
    
    async def ProcessRequest(self, request, context):
        """Process request with comprehensive error handling."""
        request_id = f"req_{self.request_count + 1}"
        self.request_count += 1
        
        logger.info(
            "Processing request with error handling",
            domain="error_handling",
            action="process_request",
            status="starting",
            request_id=request_id,
            total_requests=self.request_count
        )
        
        try:
            # Simulate various types of errors
            message = getattr(request, 'message', '')
            
            # Validate input
            if not message:
                raise ValueError("Empty message not allowed")
            
            if message.startswith("ERROR_"):
                error_type = message.replace("ERROR_", "")
                await self._simulate_error(error_type, request_id)
            
            # Normal processing
            await asyncio.sleep(0.01)  # Simulate work
            
            result = f"Processed: {message} (ID: {request_id})"
            
            logger.info(
                "Request processed successfully",
                domain="error_handling",
                action="process_request",
                status="success",
                request_id=request_id,
                result_length=len(result)
            )
            
            return type('ProcessReply', (), {'response': result})()
            
        except Exception as e:
            self.error_count += 1
            
            logger.error(
                "Request processing failed",
                domain="error_handling",
                action="process_request",
                status="error",
                request_id=request_id,
                error_type=type(e).__name__,
                error_message=str(e),
                total_errors=self.error_count
            )
            
            # Attempt recovery
            recovery_result = await self._attempt_recovery(e, request_id)
            if recovery_result:
                self.recovery_count += 1
                return recovery_result
            
            # Re-raise if recovery failed
            raise
    
    async def _simulate_error(self, error_type: str, request_id: str):
        """Simulate different types of errors for demonstration."""
        
        logger.warning(
            f"Simulating {error_type} error",
            domain="error_handling",
            action="simulate_error",
            status="simulating",
            error_type=error_type,
            request_id=request_id
        )
        
        if error_type == "TIMEOUT":
            await asyncio.sleep(2.0)  # Simulate timeout
            raise TimeoutError("Operation timed out")
        
        elif error_type == "NETWORK":
            raise TransportError("Network connection lost")
        
        elif error_type == "AUTH":
            raise SecurityError("Authentication failed")
        
        elif error_type == "VALIDATION":
            raise ValueError("Invalid input data")
        
        elif error_type == "RESOURCE":
            raise ResourceWarning("Insufficient resources")
        
        elif error_type == "PROTOCOL":
            raise ProtocolError("Protocol version mismatch")
        
        else:
            raise RPCPluginError(f"Unknown error type: {error_type}")
    
    async def _attempt_recovery(self, error: Exception, request_id: str) -> Optional[Any]:
        """Attempt to recover from errors when possible."""
        
        logger.info(
            "Attempting error recovery",
            domain="error_handling",
            action="recovery_attempt",
            status="starting",
            request_id=request_id,
            error_type=type(error).__name__
        )
        
        if isinstance(error, ValueError):
            # Recoverable validation error
            logger.info(
                "Recovering from validation error",
                domain="error_handling",
                action="recovery_attempt",
                status="success",
                request_id=request_id,
                recovery_method="default_value"
            )
            return type('ProcessReply', (), {
                'response': f"Recovered from validation error (ID: {request_id})"
            })()
        
        elif isinstance(error, ResourceWarning):
            # Recoverable resource issue
            logger.info(
                "Recovering from resource warning",
                domain="error_handling",
                action="recovery_attempt",
                status="success",
                request_id=request_id,
                recovery_method="graceful_degradation"
            )
            return type('ProcessReply', (), {
                'response': f"Processed with reduced functionality (ID: {request_id})"
            })()
        
        else:
            logger.warning(
                "Error not recoverable",
                domain="error_handling",
                action="recovery_attempt",
                status="failed",
                request_id=request_id,
                error_type=type(error).__name__
            )
            return None


class RetryPolicy:
    """Configurable retry policy for RPC operations."""
    
    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        backoff_factor: float = 2.0,
        jitter: bool = True,
        retryable_exceptions: Optional[tuple] = None
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        self.jitter = jitter
        self.retryable_exceptions = retryable_exceptions or (
            TransportError,
            TimeoutError,
            ConnectionError
        )
    
    async def execute_with_retry(self, operation, *args, **kwargs):
        """Execute operation with retry logic."""
        
        last_exception = None
        
        for attempt in range(self.max_retries + 1):
            try:
                logger.debug(
                    f"Executing operation (attempt {attempt + 1})",
                    domain="error_handling",
                    action="retry_execute",
                    status="attempting",
                    attempt=attempt + 1,
                    max_attempts=self.max_retries + 1
                )
                
                result = await operation(*args, **kwargs)
                
                if attempt > 0:
                    logger.info(
                        "Operation succeeded after retry",
                        domain="error_handling",
                        action="retry_execute",
                        status="success_after_retry",
                        successful_attempt=attempt + 1,
                        total_attempts=attempt + 1
                    )
                
                return result
                
            except Exception as e:
                last_exception = e
                
                # Check if exception is retryable
                if not isinstance(e, self.retryable_exceptions):
                    logger.error(
                        "Non-retryable exception, failing immediately",
                        domain="error_handling",
                        action="retry_execute",
                        status="non_retryable",
                        exception_type=type(e).__name__,
                        error=str(e)
                    )
                    raise
                
                # Don't retry on last attempt
                if attempt == self.max_retries:
                    logger.error(
                        "All retry attempts exhausted",
                        domain="error_handling",
                        action="retry_execute",
                        status="exhausted",
                        total_attempts=attempt + 1,
                        final_error=str(e)
                    )
                    raise
                
                # Calculate delay for next attempt
                delay = min(
                    self.base_delay * (self.backoff_factor ** attempt),
                    self.max_delay
                )
                
                if self.jitter:
                    delay += random.uniform(0, delay * 0.1)
                
                logger.warning(
                    f"Operation failed, retrying in {delay:.2f}s",
                    domain="error_handling",
                    action="retry_execute",
                    status="retrying",
                    attempt=attempt + 1,
                    error=str(e),
                    delay_seconds=delay
                )
                
                await asyncio.sleep(delay)
        
        # This should never be reached due to the logic above
        raise last_exception


class CircuitBreaker:
    """Circuit breaker pattern for preventing cascade failures."""
    
    def __init__(
        self,
        failure_threshold: int = 5,
        success_threshold: int = 3,
        timeout: float = 60.0
    ):
        self.failure_threshold = failure_threshold
        self.success_threshold = success_threshold
        self.timeout = timeout
        
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
    
    async def call(self, operation, *args, **kwargs):
        """Execute operation with circuit breaker protection."""
        
        # Check circuit state
        if self.state == "OPEN":
            if time.time() - self.last_failure_time > self.timeout:
                logger.info(
                    "Circuit breaker transitioning to HALF_OPEN",
                    domain="error_handling",
                    action="circuit_breaker",
                    status="state_change",
                    previous_state="OPEN",
                    new_state="HALF_OPEN"
                )
                self.state = "HALF_OPEN"
                self.success_count = 0
            else:
                logger.warning(
                    "Circuit breaker is OPEN, rejecting call",
                    domain="error_handling",
                    action="circuit_breaker",
                    status="rejected",
                    state="OPEN",
                    time_until_retry=self.timeout - (time.time() - self.last_failure_time)
                )
                raise Exception("Circuit breaker is OPEN")
        
        try:
            result = await operation(*args, **kwargs)
            
            # Handle success
            if self.state == "HALF_OPEN":
                self.success_count += 1
                if self.success_count >= self.success_threshold:
                    logger.info(
                        "Circuit breaker transitioning to CLOSED",
                        domain="error_handling",
                        action="circuit_breaker",
                        status="state_change",
                        previous_state="HALF_OPEN",
                        new_state="CLOSED",
                        success_count=self.success_count
                    )
                    self.state = "CLOSED"
                    self.failure_count = 0
            
            return result
            
        except Exception as e:
            # Handle failure
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.state in ["CLOSED", "HALF_OPEN"]:
                if self.failure_count >= self.failure_threshold:
                    logger.warning(
                        "Circuit breaker transitioning to OPEN",
                        domain="error_handling",
                        action="circuit_breaker",
                        status="state_change",
                        previous_state=self.state,
                        new_state="OPEN",
                        failure_count=self.failure_count
                    )
                    self.state = "OPEN"
            
            raise


async def example_7_basic_error_handling():
    """
    Example 7A: Demonstrates basic error handling patterns.
    
    Shows fundamental error handling techniques for RPC
    operations including try/catch and exception types.
    """
    print("\n" + "=" * 60)
    print("🚨 Example 7A: Basic Error Handling Patterns")
    print(" Demonstrates: Fundamental error handling techniques")
    print("=" * 60)
    
    # Configure for error handling demonstration
    configure(
        magic_cookie="error-handling-cookie",
        protocol_version=1,
        transports=["unix"],
        auto_mtls=False,
        handshake_timeout=5.0,
        connection_timeout=30.0
    )
    
    protocol = create_basic_protocol()
    handler = RobustServiceHandler()
    
    server = plugin_server(
        protocol=protocol,
        handler=handler,
        transport="unix"
    )
    
    logger.info(
        "Starting error handling demonstration server",
        domain="error_handling",
        action="server_start",
        status="starting",
        error_handling="comprehensive"
    )
    
    server_task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.5)
    
    try:
        client = plugin_client(transport="unix")
        
        # Test cases for different error scenarios
        test_cases = [
            {
                'name': 'successful_request',
                'input': 'normal_message',
                'expected': 'success'
            },
            {
                'name': 'validation_error',
                'input': 'ERROR_VALIDATION',
                'expected': 'recoverable_error'
            },
            {
                'name': 'timeout_error',
                'input': 'ERROR_TIMEOUT',
                'expected': 'non_recoverable_error'
            },
            {
                'name': 'network_error',
                'input': 'ERROR_NETWORK',
                'expected': 'non_recoverable_error'
            },
            {
                'name': 'resource_warning',
                'input': 'ERROR_RESOURCE',
                'expected': 'recoverable_error'
            }
        ]
        
        for test_case in test_cases:
            logger.info(
                f"Testing error scenario: {test_case['name']}",
                domain="error_handling",
                action="test_scenario",
                status="starting",
                scenario=test_case['name'],
                input=test_case['input'],
                expected_outcome=test_case['expected']
            )
            
            try:
                # Simulate RPC call (in real scenario, would use gRPC stub)
                await asyncio.sleep(0.1)
                
                if test_case['input'].startswith('ERROR_'):
                    # Simulate different error types
                    if 'VALIDATION' in test_case['input']:
                        result = f"Recovered: {test_case['input']}"
                    elif 'RESOURCE' in test_case['input']:
                        result = f"Degraded: {test_case['input']}"
                    else:
                        raise Exception(f"Simulated error: {test_case['input']}")
                else:
                    result = f"Success: {test_case['input']}"
                
                logger.info(
                    f"Test scenario completed: {test_case['name']}",
                    domain="error_handling",
                    action="test_scenario",
                    status="success",
                    scenario=test_case['name'],
                    result=result
                )
                
            except Exception as e:
                logger.error(
                    f"Test scenario failed: {test_case['name']}",
                    domain="error_handling",
                    action="test_scenario",
                    status="error",
                    scenario=test_case['name'],
                    error=str(e),
                    error_type=type(e).__name__
                )
        
        await client.close()
        
    finally:
        await server.stop()
        await server_task
    
    logger.info(
        "Basic error handling demonstration completed",
        domain="error_handling",
        action="demo_complete",
        status="success",
        patterns_demonstrated=["try_catch", "exception_types", "error_recovery"]
    )


async def example_7_retry_patterns():
    """
    Example 7B: Demonstrates retry patterns and policies.
    
    Shows how to implement robust retry logic with exponential
    backoff and configurable retry policies.
    """
    print("\n" + "=" * 60)
    print("🔁 Example 7B: Retry Patterns and Policies")
    print(" Demonstrates: Advanced retry logic with backoff")
    print("=" * 60)
    
    async def unreliable_operation(operation_id: int, success_rate: float = 0.3):
        """Simulate an unreliable operation for retry testing."""
        
        logger.debug(
            f"Attempting unreliable operation {operation_id}",
            domain="error_handling",
            action="unreliable_op",
            status="attempting",
            operation_id=operation_id,
            success_rate=success_rate
        )
        
        # Simulate network delay
        await asyncio.sleep(0.1)
        
        # Random failure based on success rate
        if random.random() > success_rate:
            raise TransportError(f"Simulated failure for operation {operation_id}")
        
        return f"Success result for operation {operation_id}"
    
    # Test different retry policies
    retry_policies = [
        {
            'name': 'conservative',
            'policy': RetryPolicy(max_retries=2, base_delay=0.5, backoff_factor=1.5)
        },
        {
            'name': 'aggressive',
            'policy': RetryPolicy(max_retries=5, base_delay=0.1, backoff_factor=2.0)
        },
        {
            'name': 'patient',
            'policy': RetryPolicy(max_retries=3, base_delay=1.0, backoff_factor=3.0)
        }
    ]
    
    for policy_config in retry_policies:
        policy_name = policy_config['name']
        retry_policy = policy_config['policy']
        
        logger.info(
            f"Testing retry policy: {policy_name}",
            domain="error_handling",
            action="retry_policy_test",
            status="starting",
            policy_name=policy_name,
            max_retries=retry_policy.max_retries,
            base_delay=retry_policy.base_delay,
            backoff_factor=retry_policy.backoff_factor
        )
        
        success_count = 0
        total_operations = 5
        
        for op_id in range(total_operations):
            try:
                start_time = time.time()
                
                result = await retry_policy.execute_with_retry(
                    unreliable_operation,
                    op_id,
                    0.4  # 40% success rate
                )
                
                duration = time.time() - start_time
                success_count += 1
                
                logger.info(
                    f"Operation {op_id} succeeded with {policy_name} policy",
                    domain="error_handling",
                    action="retry_success",
                    status="success",
                    operation_id=op_id,
                    policy_name=policy_name,
                    duration=duration,
                    result=result
                )
                
            except Exception as e:
                duration = time.time() - start_time
                
                logger.warning(
                    f"Operation {op_id} failed with {policy_name} policy",
                    domain="error_handling",
                    action="retry_failure",
                    status="failed",
                    operation_id=op_id,
                    policy_name=policy_name,
                    duration=duration,
                    error=str(e)
                )
        
        success_rate = (success_count / total_operations) * 100
        
        logger.info(
            f"Retry policy test completed: {policy_name}",
            domain="error_handling",
            action="retry_policy_test",
            status="completed",
            policy_name=policy_name,
            success_count=success_count,
            total_operations=total_operations,
            success_rate=f"{success_rate:.1f}%"
        )


async def example_7_circuit_breaker():
    """
    Example 7C: Demonstrates circuit breaker pattern.
    
    Shows how to implement circuit breaker pattern to prevent
    cascade failures and system overload.
    """
    print("\n" + "=" * 60)
    print("🔌 Example 7C: Circuit Breaker Pattern")
    print(" Demonstrates: Preventing cascade failures")
    print("=" * 60)
    
    async def failing_service(call_id: int, failure_rate: float = 0.8):
        """Simulate a failing downstream service."""
        
        logger.debug(
            f"Calling failing service (call {call_id})",
            domain="error_handling",
            action="failing_service",
            status="calling",
            call_id=call_id,
            failure_rate=failure_rate
        )
        
        await asyncio.sleep(0.05)  # Simulate network delay
        
        if random.random() < failure_rate:
            raise Exception(f"Service failure for call {call_id}")
        
        return f"Service success for call {call_id}"
    
    # Create circuit breaker
    circuit_breaker = CircuitBreaker(
        failure_threshold=3,
        success_threshold=2,
        timeout=5.0
    )
    
    logger.info(
        "Starting circuit breaker demonstration",
        domain="error_handling",
        action="circuit_breaker_demo",
        status="starting",
        failure_threshold=3,
        success_threshold=2,
        timeout=5.0
    )
    
    # Phase 1: Normal operation with failures (circuit should open)
    logger.info(
        "Phase 1: Demonstrating circuit opening due to failures",
        domain="error_handling",
        action="circuit_breaker_phase",
        status="starting",
        phase=1,
        description="accumulating_failures"
    )
    
    for call_id in range(10):
        try:
            result = await circuit_breaker.call(failing_service, call_id, 0.9)
            logger.info(
                f"Call {call_id} succeeded",
                domain="error_handling",
                action="circuit_call",
                status="success",
                call_id=call_id,
                circuit_state=circuit_breaker.state,
                result=result
            )
            
        except Exception as e:
            logger.warning(
                f"Call {call_id} failed",
                domain="error_handling",
                action="circuit_call",
                status="failed",
                call_id=call_id,
                circuit_state=circuit_breaker.state,
                error=str(e)
            )
        
        # Small delay between calls
        await asyncio.sleep(0.1)
    
    # Phase 2: Circuit is open, calls should be rejected immediately
    logger.info(
        "Phase 2: Circuit is open, calls rejected immediately",
        domain="error_handling",
        action="circuit_breaker_phase",
        status="starting",
        phase=2,
        description="circuit_open"
    )
    
    for call_id in range(10, 13):
        try:
            result = await circuit_breaker.call(failing_service, call_id, 0.1)
            logger.info(
                f"Call {call_id} succeeded (unexpected)",
                domain="error_handling",
                action="circuit_call",
                status="success",
                call_id=call_id,
                circuit_state=circuit_breaker.state
            )
            
        except Exception as e:
            logger.info(
                f"Call {call_id} rejected by circuit breaker",
                domain="error_handling",
                action="circuit_call",
                status="rejected",
                call_id=call_id,
                circuit_state=circuit_breaker.state,
                error=str(e)
            )
        
        await asyncio.sleep(0.1)
    
    # Phase 3: Wait for timeout, then demonstrate recovery
    logger.info(
        "Phase 3: Waiting for circuit timeout and recovery",
        domain="error_handling",
        action="circuit_breaker_phase",
        status="starting",
        phase=3,
        description="recovery_phase"
    )
    
    # Simulate waiting for timeout (shortened for demo)
    logger.info(
        "Simulating timeout wait...",
        domain="error_handling",
        action="timeout_simulation",
        status="waiting",
        actual_timeout=5.0,
        demo_timeout=0.5
    )
    await asyncio.sleep(0.5)
    
    # Force circuit to half-open state for demonstration
    circuit_breaker.last_failure_time = time.time() - 10.0
    
    # Try calls with better success rate
    for call_id in range(20, 25):
        try:
            result = await circuit_breaker.call(failing_service, call_id, 0.2)  # Better success rate
            logger.info(
                f"Recovery call {call_id} succeeded",
                domain="error_handling",
                action="circuit_call",
                status="success",
                call_id=call_id,
                circuit_state=circuit_breaker.state,
                result=result
            )
            
        except Exception as e:
            logger.warning(
                f"Recovery call {call_id} failed",
                domain="error_handling",
                action="circuit_call",
                status="failed",
                call_id=call_id,
                circuit_state=circuit_breaker.state,
                error=str(e)
            )
        
        await asyncio.sleep(0.1)
    
    logger.info(
        "Circuit breaker demonstration completed",
        domain="error_handling",
        action="circuit_breaker_demo",
        status="completed",
        final_state=circuit_breaker.state,
        total_failures=circuit_breaker.failure_count,
        pattern_benefits=["prevents_cascade_failures", "automatic_recovery", "system_protection"]
    )


async def example_7_error_monitoring():
    """
    Example 7D: Demonstrates error monitoring and metrics.
    
    Shows how to implement comprehensive error monitoring,
    metrics collection, and alerting for production systems.
    """
    print("\n" + "=" * 60)
    print("📊 Example 7D: Error Monitoring and Metrics")
    print(" Demonstrates: Production error monitoring patterns")
    print("=" * 60)
    
    class ErrorMonitor:
        """Error monitoring and metrics collection."""
        
        def __init__(self):
            self.error_counts = {}
            self.error_rates = {}
            self.recovery_stats = {}
            self.start_time = time.time()
        
        def record_error(self, error_type: str, recoverable: bool = False):
            """Record an error occurrence."""
            
            self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
            
            if recoverable:
                self.recovery_stats[error_type] = self.recovery_stats.get(error_type, 0) + 1
            
            # Calculate error rate
            uptime_minutes = (time.time() - self.start_time) / 60
            self.error_rates[error_type] = self.error_counts[error_type] / max(uptime_minutes, 1)
        
        def get_error_summary(self) -> Dict[str, Any]:
            """Get comprehensive error summary."""
            
            total_errors = sum(self.error_counts.values())
            total_recoveries = sum(self.recovery_stats.values())
            uptime_minutes = (time.time() - self.start_time) / 60
            
            return {
                'total_errors': total_errors,
                'total_recoveries': total_recoveries,
                'recovery_rate': (total_recoveries / max(total_errors, 1)) * 100,
                'uptime_minutes': uptime_minutes,
                'errors_per_minute': total_errors / max(uptime_minutes, 1),
                'error_breakdown': self.error_counts,
                'recovery_breakdown': self.recovery_stats,
                'error_rates': self.error_rates
            }
        
        def check_alert_conditions(self) -> List[Dict[str, Any]]:
            """Check for alerting conditions."""
            
            alerts = []
            
            # High error rate alert
            if sum(self.error_rates.values()) > 10:  # More than 10 errors per minute
                alerts.append({
                    'type': 'high_error_rate',
                    'severity': 'warning',
                    'message': f"High error rate: {sum(self.error_rates.values()):.1f} errors/min"
                })
            
            # Low recovery rate alert
            total_errors = sum(self.error_counts.values())
            total_recoveries = sum(self.recovery_stats.values())
            recovery_rate = (total_recoveries / max(total_errors, 1)) * 100
            
            if recovery_rate < 50 and total_errors > 5:
                alerts.append({
                    'type': 'low_recovery_rate',
                    'severity': 'critical',
                    'message': f"Low recovery rate: {recovery_rate:.1f}%"
                })
            
            # Specific error type alerts
            for error_type, count in self.error_counts.items():
                if count > 5:
                    alerts.append({
                        'type': 'frequent_error',
                        'severity': 'warning',
                        'message': f"Frequent {error_type} errors: {count} occurrences"
                    })
            
            return alerts
    
    # Create error monitor
    error_monitor = ErrorMonitor()
    
    logger.info(
        "Starting error monitoring demonstration",
        domain="error_handling",
        action="monitoring_start",
        status="starting",
        monitoring_capabilities=["error_counting", "recovery_tracking", "rate_calculation", "alerting"]
    )
    
    # Simulate various error scenarios
    error_scenarios = [
        {'type': 'TransportError', 'count': 3, 'recoverable': False},
        {'type': 'ValidationError', 'count': 8, 'recoverable': True},
        {'type': 'TimeoutError', 'count': 2, 'recoverable': False},
        {'type': 'ResourceError', 'count': 5, 'recoverable': True},
        {'type': 'SecurityError', 'count': 1, 'recoverable': False},
    ]
    
    for scenario in error_scenarios:
        logger.info(
            f"Simulating {scenario['type']} errors",
            domain="error_handling",
            action="error_simulation",
            status="starting",
            error_type=scenario['type'],
            count=scenario['count'],
            recoverable=scenario['recoverable']
        )
        
        for i in range(scenario['count']):
            # Record error
            error_monitor.record_error(scenario['type'], scenario['recoverable'])
            
            # Simulate some time between errors
            await asyncio.sleep(0.05)
            
            logger.debug(
                f"Recorded {scenario['type']} error {i + 1}",
                domain="error_handling",
                action="error_record",
                status="recorded",
                error_type=scenario['type'],
                occurrence=i + 1,
                recoverable=scenario['recoverable']
            )
    
    # Generate error summary
    error_summary = error_monitor.get_error_summary()
    
    logger.info(
        "Error monitoring summary",
        domain="error_handling",
        action="monitoring_summary",
        status="completed",
        **error_summary
    )
    
    # Check for alerts
    alerts = error_monitor.check_alert_conditions()
    
    if alerts:
        for alert in alerts:
            logger.warning(
                f"Alert triggered: {alert['type']}",
                domain="error_handling",
                action="alert",
                status="triggered",
                alert_type=alert['type'],
                severity=alert['severity'],
                message=alert['message']
            )
    else:
        logger.info(
            "No alerts triggered",
            domain="error_handling",
            action="alert_check",
            status="clear",
            alert_conditions="all_normal"
        )
    
    # Demonstrate metrics export (would integrate with monitoring systems)
    metrics_export = {
        'timestamp': time.time(),
        'service': 'pyvider-rpcplugin-example',
        'metrics': error_summary,
        'alerts': alerts
    }
    
    logger.info(
        "Metrics exported for monitoring system",
        domain="error_handling",
        action="metrics_export",
        status="exported",
        export_format="json",
        integration_targets=["prometheus", "datadog", "cloudwatch"]
    )


async def main():
    """Run all error handling examples."""
    print("🚨 pyvider-rpcplugin Error Handling Examples")
    print("============================================")
    
    try:
        # Run each error handling example
        await example_7_basic_error_handling()
        await example_7_retry_patterns()
        await example_7_circuit_breaker()
        await example_7_error_monitoring()
        
        print("\n" + "=" * 60)
        print("✅ All Error Handling Examples Completed Successfully!")
        print("=" * 60)
        print("\n🚨 Error Handling Best Practices:")
        print("  • Implement comprehensive exception handling with specific error types")
        print("  • Use retry policies with exponential backoff for transient failures")
        print("  • Deploy circuit breakers to prevent cascade failures")
        print("  • Monitor error rates and recovery patterns for system health")
        print("  • Design graceful degradation for non-critical functionality")
        print("\n📖 Next Steps:")
        print("  • See example 08_production_config.py for production-ready error handling")
        print("  • Try example 06_async_patterns.py for async error handling patterns")
        print("  • Check docs/troubleshooting.md for debugging common issues")
        
    except Exception as e:
        logger.error(
            "Error handling example failed",
            domain="examples",
            action="run",
            status="error",
            error=str(e)
        )
        raise


if __name__ == "__main__":
    asyncio.run(main())
