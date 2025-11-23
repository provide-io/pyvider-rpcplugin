# Contributing Guide

Thank you for your interest in contributing to Pyvider RPC Plugin! This guide covers development setup, workflows, code standards, testing, and CI/CD automation.

## Getting Started

### Prerequisites

Before you begin, ensure you have:

- **Python 3.11+** installed
- **Git** for version control
- **Docker** for testing (optional but recommended)
- A **GitHub account** for submitting changes

### Development Environment Setup

1. **Fork and Clone the Repository**

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/<username>/pyvider-rpcplugin.git
cd pyvider-rpcplugin

# Add the upstream repository
git remote add upstream https://github.com/provide-io/pyvider-rpcplugin.git
```

2. **Set Up Development Environment**

```bash
# Set up development environment with all dependencies
uv sync --all-groups

# Verify installation
uv run pytest --version
```

3. **Verify Installation**

```bash
# Run tests to ensure everything works
uv run pytest

# Check code formatting
uv run ruff check .

# Run type checking
uv run pyre check
```

## Development Workflow

### Branch Strategy

We use a **feature branch workflow**:

```bash
# Create a new feature branch
git checkout -b feature/<feature-name>

# Make your changes
# ... code, test, commit ...

# Push to your fork
git push origin feature/<feature-name>

# Create a Pull Request on GitHub
```

### Making Changes

=== "Write Tests First"

    **TDD approach recommended:**

    ```python
    # tests/test_new_feature.py
    import pytest
    from pyvider.new_feature import NewFeature

    class TestNewFeature:
        async def test_basic_functionality(self):
            feature = NewFeature()
            result = await feature.do_something()
            assert result == "expected_result"

        async def test_error_handling(self):
            feature = NewFeature()
            with pytest.raises(ValueError):
                await feature.do_something_invalid()
    ```

=== "Implement the Feature"

    ```python
    # src/pyvider/new_feature.py
    from typing import Any
    import asyncio

    class NewFeature:
        """A new feature for the RPC Plugin system."""

        def __init__(self):
            self._initialized = False

        async def do_something(self) -> str:
            """Perform the main functionality."""
            if not self._initialized:
                await self._initialize()

            return "expected_result"

        async def do_something_invalid(self) -> None:
            """Example method that raises an error."""
            raise ValueError("Invalid operation")

        async def _initialize(self) -> None:
            """Initialize the feature."""
            self._initialized = True
    ```

=== "Update Documentation"

    ```python
    # Update docstrings with comprehensive information
    class NewFeature:
        """A new feature for the RPC plugin system.

        This feature provides enhanced functionality for RPC operations
        including advanced error handling and performance optimizations.

        Example:
            ```python
            feature = NewFeature()
            result = await feature.do_something()
            print(result)  # "expected_result"
            ```

        Attributes:
            initialized: Whether the feature has been initialized.
        """
    ```

=== "Run Quality Checks"

    ```bash
    # Run all tests
    uv run pytest -v

    # Check code formatting
    uv run ruff check . --fix

    # Run type checking
    uv run pyre check

    # Check test coverage
    uv run pytest --cov=src --cov-report=html
    ```

## Code Standards

### Python Style Guide

We follow **modern Python practices** with these guidelines:

#### Type Annotations

```python
# ✅ Good - Use modern typing
from typing import Any
from collections.abc import Callable, Awaitable

def process_data(
    data: dict[str, Any],
    callback: Callable[[str], Awaitable[bool]]
) -> list[str]:
    return list(data.keys())

# ✅ Good - Use modern Python 3.11+ typing
from collections.abc import Callable
from typing import Any

def process_data(
    data: dict[str, Any],
    callback: Callable[[str], bool] | None = None
) -> list[str]:
    return list(data.keys())
```

#### Modern Python Features

```python
# ✅ Good - Use match statements (Python 3.11+)
match response_type:
    case "success":
        return handle_success(data)
    case "error":
        return handle_error(data)
    case _:
        raise ValueError(f"Unknown response type: {response_type}")

# ✅ Good - Use union operator for types
def process_value(value: str | int) -> str:
    return str(value)

# ✅ Good - Use walrus operator where appropriate
if (result := expensive_function()) is not None:
    return result
```

#### Error Handling

```python
# ✅ Good - Specific exception handling
try:
    result = await risky_operation()
except ConnectionError as e:
    logger.error(f"Connection failed: {e}")
    raise RPCConnectionError(f"Failed to connect: {e}") from e
except TimeoutError as e:
    logger.warning(f"Operation timed out: {e}")
    raise RPCTimeoutError("Operation timed out") from e

# ✅ Good - Custom exception hierarchy
class RPCPluginError(Exception):
    """Base exception for RPC plugin errors."""
    pass

class RPCConnectionError(RPCPluginError):
    """Raised when RPC connection fails."""
    pass

class RPCTimeoutError(RPCPluginError):
    """Raised when RPC operation times out."""
    pass
```

### Documentation Standards

#### Docstring Format

We use **Google-style docstrings**:

````python
async def create_connection(
    host: str,
    port: int,
    timeout: float = 30.0,
    ssl_context: Any | None = None
) -> RPCConnection:
    """Create a new RPC connection.

    Establishes a connection to the specified RPC server with optional
    SSL encryption and configurable timeout.

    Args:
        host: The hostname or IP address of the RPC server.
        port: The port number to connect to.
        timeout: Connection timeout in seconds. Defaults to 30.0.
        ssl_context: Optional SSL context for encrypted connections.

    Returns:
        An established RPC connection ready for use.

    Raises:
        RPCConnectionError: If the connection cannot be established.
        RPCTimeoutError: If the connection times out.
        ValueError: If host or port parameters are invalid.

    Example:
        ```python
        # Basic connection
        conn = await create_connection("localhost", 50051)

        # SSL connection with custom timeout
        ssl_ctx = ssl.create_default_context()
        conn = await create_connection(
            "secure.example.com",
            443,
            timeout=10.0,
            ssl_context=ssl_ctx
        )
        ```
    """
    if not host:
        raise ValueError("Host cannot be empty")
    if not 1 <= port <= 65535:
        raise ValueError(f"Invalid port: {port}")

    # Implementation here...
````

#### Code Comments

```python
# ✅ Good - Explain complex logic
async def optimize_connection_pool(self) -> None:
    """Optimize connection pool based on current usage patterns."""
    # Calculate optimal pool size based on request rate and latency
    # Using Little's Law: L = λ * W (avg requests = rate * avg response time)
    current_rate = self._get_request_rate()
    avg_latency = self._get_average_latency()
    optimal_size = max(1, int(current_rate * avg_latency * 1.2))  # 20% buffer

    await self._resize_pool(optimal_size)

# ❌ Bad - Obvious comments
port = 50051  # Set port to 50051
```

## Testing Guidelines

### Test Structure

We use **pytest** with these patterns:

```python
# tests/test_connection_manager.py
import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from pyvider.connection import ConnectionManager, RPCConnection

class TestConnectionManager:
    """Test suite for ConnectionManager class."""

    @pytest.fixture
    async def manager(self):
        """Create a connection manager for testing."""
        mgr = ConnectionManager(max_connections=5)
        yield mgr
        await mgr.cleanup()

    @pytest.fixture
    def mock_connection(self):
        """Create a mock RPC connection."""
        conn = Mock(spec=RPCConnection)
        conn.is_healthy = AsyncMock(return_value=True)
        conn.close = AsyncMock()
        return conn

    async def test_create_connection_success(self, manager):
        """Test successful connection creation."""
        with patch('pyvider.connection.create_connection') as mock_create:
            mock_create.return_value = Mock(spec=RPCConnection)

            conn = await manager.get_connection("localhost", 50051)

            assert conn is not None
            mock_create.assert_called_once_with("localhost", 50051)
```

### Test Categories

=== "Unit Tests"

    Test individual components in isolation:

    ```python
    def test_config_validation():
        """Test configuration validation."""
        config = ServerConfig(port=50051)
        assert config.port == 50051
    ```

=== "Integration Tests"

    Test component interactions:

    ```python
    @pytest.mark.integration
    async def test_full_rpc_workflow():
        """Test complete RPC workflow from client to server."""
        server = await create_test_server()
        try:
            await server.start()

            client = await create_test_client(server.port)
            try:
                response = await client.echo("test message")
                assert response.message == "test message"
            finally:
                await client.close()
        finally:
            await server.stop()
    ```

=== "Performance Tests"

    Test performance characteristics:

    ```python
    @pytest.mark.performance
    async def test_high_throughput():
        """Test server performance under high load."""
        async def make_requests(client, count):
            tasks = []
            for i in range(count):
                tasks.append(client.echo(f"message-{i}"))
            return await asyncio.gather(*tasks)

        server = await create_test_server()
        try:
            await server.start()
            client = await create_test_client(server.port)

            start_time = time.time()
            results = await make_requests(client, 1000)
            duration = time.time() - start_time

            assert len(results) == 1000
            assert duration < 10.0

        finally:
            await client.close()
            await server.stop()
    ```

## CI/CD Pipeline

### GitHub Actions Workflows

=== "Main CI Pipeline"

    **Location:** `.github/workflows/ci.yml`

    ```yaml
    name: CI

    on:
      push:
        branches: [main, develop]
      pull_request:
        branches: [main]

    jobs:
      test:
        runs-on: ${{ matrix.os }}
        strategy:
          matrix:
            os: [ubuntu-latest, macos-latest, windows-latest]
            python-version: ["3.11", "3.12"]

        steps:
        - uses: actions/checkout@v4

        - name: Set up Python
          uses: actions/setup-python@v5
          with:
            python-version: ${{ matrix.python-version }}

        - name: Install dependencies
          run: |
            python -m pip install --upgrade pip uv
            uv pip install -e ".[dev,test]"

        - name: Run tests
          run: pytest --cov=pyvider.rpcplugin --cov-report=xml

        - name: Upload coverage
          uses: codecov/codecov-action@v4
          with:
            file: ./coverage.xml
    ```

=== "Release Workflow"

    **Location:** `.github/workflows/release.yml`

    ```yaml
    name: Release

    on:
      push:
        tags: ['v*']

    jobs:
      build-and-publish:
        runs-on: ubuntu-latest

        steps:
        - uses: actions/checkout@v4

        - name: Set up Python
          uses: actions/setup-python@v5

        - name: Build distribution
          run: python -m build

        - name: Publish to PyPI
          env:
            TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
          run: twine upload dist/*
    ```

### Code Quality Configuration

=== "Linting (Ruff)"

    **pyproject.toml:**

    ```toml
    [tool.ruff]
    target-version = "py311"
    line-length = 88
    select = [
        "E",   # pycodestyle errors
        "W",   # pycodestyle warnings
        "F",   # pyflakes
        "I",   # isort
        "B",   # flake8-bugbear
        "C4",  # flake8-comprehensions
        "UP",  # pyupgrade
    ]
    ignore = ["E501"]
    exclude = ["*_pb2.py", "*_pb2_grpc.py"]
    ```

=== "Type Checking (Mypy)"

    **pyproject.toml:**

    ```toml
    [tool.mypy]
    python_version = "3.11"
    warn_return_any = true
    warn_unused_configs = true
    disallow_untyped_defs = true
    no_implicit_optional = true
    check_untyped_defs = true
    show_error_codes = true
    exclude = ["*_pb2.py", "*_pb2_grpc.py"]
    ```

=== "Testing (Pytest)"

    **pyproject.toml:**

    ```toml
    [tool.pytest.ini_options]
    minversion = "7.0"
    testpaths = ["tests"]
    asyncio_mode = "auto"
    markers = [
        "slow: marks tests as slow",
        "integration: marks integration tests",
        "benchmark: marks performance tests"
    ]
    addopts = """
        -ra
        --strict-markers
        --cov=pyvider.rpcplugin
        --cov-branch
        --cov-report=term-missing
    """
    ```

### Pre-commit Hooks

**.pre-commit-config.yaml:**

```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.3.0
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.9.0
    hooks:
      - id: mypy
        additional_dependencies: [types-all]
        exclude: "_pb2(_grpc)?\\.py$"

  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.7
    hooks:
      - id: bandit
        args: [-r, src/]
```
````

## CI/CD Pipeline

### GitHub Actions Workflows

=== "Main CI Pipeline"

````
**Location:** `.github/workflows/ci.yml`

```yaml
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        python-version: ["3.11", "3.12"]

    steps:
    - uses: actions/checkout@v4

    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: ${{ matrix.python-version }}

    - name: Install dependencies
      run: |
        curl -LsSf https://astral.sh/uv/install.sh | sh
        uv pip install -e ".[dev,test]"

    - name: Run tests
      run: pytest --cov=pyvider.rpcplugin --cov-report=xml

    - name: Upload coverage
      uses: codecov/codecov-action@v4
      with:
        file: ./coverage.xml
```
````

=== "Release Workflow"

````
**Location:** `.github/workflows/release.yml`

```yaml
name: Release

on:
  push:
    tags: ['v*']

jobs:
  build-and-publish:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v4

    - name: Set up Python
      uses: actions/setup-python@v5

    - name: Build distribution
      run: python -m build

    - name: Publish to PyPI
      env:
        TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
      run: twine upload dist/*
```
````

### Code Quality Configuration

=== "Linting (Ruff)"

````
**pyproject.toml:**

```toml
[tool.ruff]
target-version = "py311"
line-length = 88
select = [
    "E",   # pycodestyle errors
    "W",   # pycodestyle warnings
    "F",   # pyflakes
    "I",   # isort
    "B",   # flake8-bugbear
    "C4",  # flake8-comprehensions
    "UP",  # pyupgrade
]
ignore = ["E501"]
exclude = ["*_pb2.py", "*_pb2_grpc.py"]
```
````

=== "Type Checking (Mypy)"

````
**pyproject.toml:**

```toml
[tool.mypy]
python_version = "3.11"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
no_implicit_optional = true
check_untyped_defs = true
show_error_codes = true
exclude = ["*_pb2.py", "*_pb2_grpc.py"]
```
````

=== "Testing (Pytest)"

````
**pyproject.toml:**

```toml
[tool.pytest.ini_options]
minversion = "7.0"
testpaths = ["tests"]
asyncio_mode = "auto"
markers = [
    "slow: marks tests as slow",
    "integration: marks integration tests",
    "benchmark: marks performance tests"
]
addopts = """
    -ra
    --strict-markers
    --cov=pyvider.rpcplugin
    --cov-branch
    --cov-report=term-missing
"""
```
````

### Pre-commit Hooks

**.pre-commit-config.yaml:**

```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.3.0
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.9.0
    hooks:
      - id: mypy
        additional_dependencies: [types-all]
        exclude: "_pb2(_grpc)?\\.py$"

  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.7
    hooks:
      - id: bandit
        args: [-r, src/]
```

### Release Management

=== "Semantic Versioning"

````
**Version Bumping Script:**

```bash
#!/bin/bash
# scripts/bump-version.sh

set -e

BUMP_TYPE=${1:-patch}  # major, minor, patch
CURRENT=$(python -c "import pyvider.rpcplugin; print(pyvider.rpcplugin.__version__)")

case $BUMP_TYPE in
    major) NEW=$(echo $CURRENT | awk -F. '{printf "%d.0.0", $1+1}') ;;
    minor) NEW=$(echo $CURRENT | awk -F. '{printf "%d.%d.0", $1, $2+1}') ;;
    patch) NEW=$(echo $CURRENT | awk -F. '{printf "%d.%d.%d", $1, $2, $3+1}') ;;
esac

echo "Bumping version: $CURRENT → $NEW"
sed -i "s/__version__ = \"$CURRENT\"/__version__ = \"$NEW\"/" src/pyvider/rpcplugin/__init__.py
git add -A
git commit -m "Release v$NEW"
git tag -a "v$NEW" -m "Release version $NEW"
```
````

=== "Release Notes Template"

````
```markdown
## [VERSION] - DATE

### 🎯 Highlights
- Major feature or improvement
- Performance enhancement
- Security update

### ✨ Added
- New feature description

### 🔄 Changed
- Updated behavior

### 🐛 Fixed
- Bug fix description

### ⚠️ Breaking Changes
- Breaking change description
- Migration guide
```
````

### Release Management

=== "Semantic Versioning"

    **Version Bumping Script:**

    ```bash
    #!/bin/bash
    # scripts/bump-version.sh

    set -e

    BUMP_TYPE=${1:-patch}  # major, minor, patch
    CURRENT=$(python -c "import pyvider.rpcplugin; print(pyvider.rpcplugin.__version__)")

    case $BUMP_TYPE in
        major) NEW=$(echo $CURRENT | awk -F. '{printf "%d.0.0", $1+1}') ;;
        minor) NEW=$(echo $CURRENT | awk -F. '{printf "%d.%d.0", $1, $2+1}') ;;
        patch) NEW=$(echo $CURRENT | awk -F. '{printf "%d.%d.%d", $1, $2, $3+1}') ;;
    esac

    echo "Bumping version: $CURRENT → $NEW"
    sed -i "s/__version__ = \"$CURRENT\"/__version__ = \"$NEW\"/" src/pyvider/rpcplugin/__init__.py
    git add -A
    git commit -m "Release v$NEW"
    git tag -a "v$NEW" -m "Release version $NEW"
    ```

=== "Release Notes Template"

    ```markdown
    ## [VERSION] - DATE

    ### 🎯 Highlights
    - Major feature or improvement
    - Performance enhancement
    - Security update

    ### ✨ Added
    - New feature description

    ### 🔄 Changed
    - Updated behavior

    ### 🐛 Fixed
    - Bug fix description

    ### ⚠️ Breaking Changes
    - Breaking change description
    - Migration guide
    ```

## Pull Request Process

### Before Submitting

1. **Update from upstream:**

```bash
git fetch upstream
git rebase upstream/main
```

2. **Run full test suite:**

```bash
# Run all tests with coverage
uv run pytest --cov=src --cov-report=term-missing

# Check for any regressions
uv run pytest tests/integration/

# Performance regression tests
uv run pytest tests/performance/ -v
```

3. **Update documentation:**

```bash
# Build docs locally
mkdocs serve

# Check for broken links
mkdocs build --strict
```

### PR Template

When creating a pull request, include:

```markdown
## Description
Brief description of what this PR does and why.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Performance tests added/updated (if applicable)
- [ ] Manual testing completed

## Checklist
- [ ] Code follows the project style guidelines
- [ ] Self-review of code completed
- [ ] Code is commented, particularly in hard-to-understand areas
- [ ] Corresponding changes to documentation made
- [ ] No new warnings introduced
- [ ] All tests pass locally

## Performance Impact
Describe any performance implications of these changes.

## Breaking Changes
Describe any breaking changes and migration path.
```

### Review Process

1. **Automated Checks** - CI runs tests, linting, and type checking
1. **Code Review** - Maintainers review for code quality and design
1. **Testing** - Changes are tested in various environments
1. **Documentation** - Documentation is reviewed for accuracy
1. **Approval** - Required approvals from maintainers

## Issue Reporting

### Bug Reports

Use the bug report template:

```markdown
**Describe the Bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. See error

**Expected Behavior**
A clear description of what you expected to happen.

**Environment:**
- OS: [e.g. macOS 12.0]
- Python Version: [e.g. 3.11.5]
- Pyvider RPC Plugin Version: [e.g. 1.0.0]

**Logs**
```

Include relevant log output here

```
```
```

### Feature Requests

```markdown
**Is your feature request related to a problem?**
A clear description of what the problem is.

**Describe the solution you'd like**
A clear description of what you want to happen.

**Describe alternatives you've considered**
Alternative solutions or features you've considered.
```

## Community Guidelines

### Code of Conduct

We are committed to providing a welcoming and inclusive experience for everyone. Please:

- **Be respectful** in all interactions
- **Be constructive** when providing feedback
- **Be patient** with new contributors
- **Be open** to different perspectives

### Communication Channels

- **GitHub Issues** - Bug reports and feature requests
- **GitHub Discussions** - Questions and community discussion
- **Pull Request Reviews** - Code discussions

### Recognition

We acknowledge all contributors in our README and release notes. Contributors who make significant contributions may be invited to join the maintainer team.

## Advanced Topics

### Custom Transport Implementation

If you're implementing a new transport:

```python
# src/pyvider/transport/custom_transport.py
from pyvider.transport.base import BaseTransport
from typing import Any

class CustomTransport(BaseTransport):
    """Custom transport implementation."""

    async def connect(self, address: str) -> Any:
        """Implement connection logic."""
        # Your implementation here
        pass

    async def send(self, data: bytes) -> None:
        """Implement send logic."""
        # Your implementation here
        pass

    async def receive(self) -> bytes:
        """Implement receive logic."""
        # Your implementation here
        pass

# tests/test_custom_transport.py
class TestCustomTransport:
    async def test_basic_functionality(self):
        transport = CustomTransport()
        # Test your implementation
        pass
```

### Performance Testing

For performance-critical changes:

```python
# tests/performance/test_custom_feature.py
import asyncio
import time
import statistics

@pytest.mark.benchmark
async def test_performance_baseline():
    """Establish performance baseline for new features."""
    iterations = 1000
    times = []

    for _ in range(iterations):
        start = time.perf_counter()
        await your_function()
        end = time.perf_counter()
        times.append(end - start)

    # Statistical analysis
    mean_time = statistics.mean(times)
    median_time = statistics.median(times)
    p95_time = statistics.quantiles(times, n=20)[18]  # 95th percentile

    # Assert performance requirements
    assert mean_time < 0.001  # Should complete in under 1ms on average
    assert p95_time < 0.005   # 95% should complete in under 5ms
```

## Best Practices

1. **Branch Protection** - Require PR reviews and passing CI
2. **Automated Testing** - Run tests on every push
3. **Code Coverage** - Maintain >80% coverage
4. **Security Scanning** - Regular dependency and code scanning
5. **Performance Monitoring** - Track benchmarks over time
6. **Semantic Versioning** - Follow semver for releases
7. **Documentation** - Update docs with code changes
8. **Dependency Updates** - Keep dependencies current and secure

## See Also

- [Testing Guide](testing/) - Comprehensive testing documentation
- [Architecture](architecture/) - Internal system design
- [Troubleshooting](troubleshooting/) - Common development issues

Thank you for contributing to Pyvider RPC Plugin! Your contributions help make this project better for everyone.
