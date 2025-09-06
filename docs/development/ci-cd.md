# CI/CD Pipeline

Comprehensive continuous integration and deployment setup for Pyvider RPC Plugin using GitHub Actions, automated testing, and release management.

## GitHub Actions Workflows

### Main CI Pipeline

**.github/workflows/ci.yml**
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
      run: |
        pytest --cov=pyvider.rpcplugin --cov-report=xml
    
    - name: Upload coverage
      uses: codecov/codecov-action@v4
      with:
        file: ./coverage.xml
        flags: unittests
        name: codecov-${{ matrix.os }}-py${{ matrix.python-version }}

  lint:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: "3.11"
    
    - name: Run linters
      run: |
        pip install ruff mypy
        ruff check src tests
        mypy src/

  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Security scan
      run: |
        pip install bandit safety
        bandit -r src/
        safety check
```

### Release Workflow

**.github/workflows/release.yml**
```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build-and-publish:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v5
      with:
        python-version: "3.11"
    
    - name: Install build tools
      run: |
        pip install --upgrade build twine
    
    - name: Build distribution
      run: python -m build
    
    - name: Publish to PyPI
      env:
        TWINE_USERNAME: __token__
        TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
      run: |
        twine upload dist/*
    
    - name: Create GitHub Release
      uses: softprops/action-gh-release@v1
      with:
        files: dist/*
        generate_release_notes: true
```

## Testing Strategy

### Test Matrix

| Component | Test Type | Coverage Target | Tools |
|-----------|-----------|-----------------|-------|
| Core | Unit | 90% | pytest, pytest-cov |
| Transport | Integration | 85% | pytest-asyncio |
| Protocol | Unit + Integration | 88% | pytest, mock |
| Security | Security | N/A | bandit, safety |
| Performance | Benchmark | N/A | pytest-benchmark |

### Test Configuration

**pyproject.toml**
```toml
[tool.pytest.ini_options]
minversion = "7.0"
testpaths = ["tests"]
python_files = ["test_*.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]
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
    --cov-report=html
    --cov-report=xml
"""

[tool.coverage.run]
source = ["src"]
omit = ["*/tests/*", "*/*_pb2*.py"]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "raise AssertionError",
    "raise NotImplementedError",
    "if __name__ == .__main__.:",
    "if TYPE_CHECKING:"
]
```

## Code Quality

### Linting Configuration

**pyproject.toml**
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
ignore = ["E501"]  # line too long
exclude = ["*_pb2.py", "*_pb2_grpc.py"]

[tool.ruff.per-file-ignores]
"tests/*" = ["S101"]  # assert allowed in tests

[tool.mypy]
python_version = "3.11"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_any_unimported = false
no_implicit_optional = true
check_untyped_defs = true
show_error_codes = true
exclude = ["*_pb2.py", "*_pb2_grpc.py"]
```

### Pre-commit Hooks

**.pre-commit-config.yaml**
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

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files
```

## Docker Support

### Multi-stage Dockerfile

```dockerfile
# Build stage
FROM python:3.11-slim as builder

WORKDIR /app
COPY pyproject.toml .
COPY src/ src/

RUN pip install --upgrade pip build && \
    python -m build --wheel

# Runtime stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy wheel from builder
COPY --from=builder /app/dist/*.whl /tmp/
RUN pip install /tmp/*.whl && rm /tmp/*.whl

# Create non-root user
RUN useradd -m -U appuser && \
    chown -R appuser:appuser /app
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import pyvider.rpcplugin; print('healthy')" || exit 1

ENTRYPOINT ["python", "-m", "pyvider.rpcplugin"]
```

### Docker Compose for Testing

**docker-compose.test.yml**
```yaml
version: '3.8'

services:
  test:
    build:
      context: .
      target: builder
    command: |
      sh -c "
        pip install -e '.[dev,test]' &&
        pytest --cov=pyvider.rpcplugin
      "
    volumes:
      - .:/app
      - test-cache:/root/.cache

  integration:
    build: .
    depends_on:
      - test-server
    environment:
      PLUGIN_SERVER_HOST: test-server
      PLUGIN_SERVER_PORT: 50051
    command: pytest tests/integration/

  test-server:
    build: .
    command: python -m pyvider.rpcplugin.server
    ports:
      - "50051:50051"

volumes:
  test-cache:
```

## Performance Testing

### Benchmark Suite

**tests/benchmarks/test_performance.py**
```python
import pytest
from pyvider.rpcplugin import plugin_server, plugin_client

@pytest.mark.benchmark
def test_rpc_throughput(benchmark):
    """Benchmark RPC throughput."""
    
    async def make_calls():
        client = await plugin_client(host="localhost", port=50051)
        
        for _ in range(1000):
            await client.call("Echo", message="test")
        
        await client.close()
    
    result = benchmark(asyncio.run, make_calls)
    assert result is not None

@pytest.mark.benchmark
def test_connection_pool(benchmark):
    """Benchmark connection pooling."""
    
    async def pool_operations():
        pool = ConnectionPool(size=10)
        await pool.initialize()
        
        tasks = []
        for _ in range(100):
            conn = await pool.acquire()
            tasks.append(pool.release(conn))
        
        await asyncio.gather(*tasks)
        await pool.close_all()
    
    benchmark(asyncio.run, pool_operations)
```

### Performance Monitoring

**GitHub Action for Performance**
```yaml
name: Performance

on:
  pull_request:
    paths:
      - 'src/**'
      - 'tests/benchmarks/**'

jobs:
  benchmark:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Run benchmarks
      run: |
        pip install -e ".[test]"
        pytest tests/benchmarks/ --benchmark-json=benchmark.json
    
    - name: Store benchmark results
      uses: benchmark-action/github-action-benchmark@v1
      with:
        tool: 'pytest'
        output-file-path: benchmark.json
        github-token: ${{ secrets.GITHUB_TOKEN }}
        auto-push: true
        alert-threshold: '150%'
        comment-on-alert: true
        fail-on-alert: true
```

## Release Management

### Semantic Versioning

**Version Bumping Script**
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

# Update version
sed -i "s/__version__ = \"$CURRENT\"/__version__ = \"$NEW\"/" src/pyvider/rpcplugin/__init__.py

# Create git tag
git add -A
git commit -m "Release v$NEW"
git tag -a "v$NEW" -m "Release version $NEW"

echo "✅ Version bumped to $NEW"
echo "📦 Push with: git push && git push --tags"
```

### Changelog Generation

**Release Notes Template**
```markdown
## [VERSION] - DATE

### 🎯 Highlights
- Major feature or improvement
- Performance enhancement
- Security update

### ✨ Added
- New feature description
- New API endpoint

### 🔄 Changed
- Updated behavior
- Improved performance

### 🐛 Fixed
- Bug fix description
- Security vulnerability patch

### 📚 Documentation
- Documentation improvements
- New examples

### ⚠️ Breaking Changes
- Breaking change description
- Migration guide

### 🙏 Contributors
- @contributor1
- @contributor2
```

## Deployment

### PyPI Publishing

**Automated via GitHub Actions on tag push:**
1. Tag push triggers release workflow
2. Build wheel and sdist
3. Upload to PyPI using API token
4. Create GitHub release with artifacts

### Container Registry

**Push to GitHub Container Registry:**
```yaml
- name: Login to GitHub Container Registry
  uses: docker/login-action@v3
  with:
    registry: ghcr.io
    username: ${{ github.actor }}
    password: ${{ secrets.GITHUB_TOKEN }}

- name: Build and push
  uses: docker/build-push-action@v5
  with:
    push: true
    tags: |
      ghcr.io/${{ github.repository }}:latest
      ghcr.io/${{ github.repository }}:${{ github.ref_name }}
```

## Monitoring

### Status Badges

```markdown
[![CI](https://github.com/provide-io/pyvider-rpcplugin/actions/workflows/ci.yml/badge.svg)](https://github.com/provide-io/pyvider-rpcplugin/actions)
[![Coverage](https://codecov.io/gh/provide-io/pyvider-rpcplugin/branch/main/graph/badge.svg)](https://codecov.io/gh/provide-io/pyvider-rpcplugin)
[![PyPI](https://img.shields.io/pypi/v/pyvider-rpcplugin.svg)](https://pypi.org/project/pyvider-rpcplugin/)
[![Python](https://img.shields.io/pypi/pyversions/pyvider-rpcplugin.svg)](https://pypi.org/project/pyvider-rpcplugin/)
[![License](https://img.shields.io/github/license/provide-io/pyvider-rpcplugin.svg)](https://github.com/provide-io/pyvider-rpcplugin/blob/main/LICENSE)
```

### Dependency Updates

**Dependabot Configuration (.github/dependabot.yml):**
```yaml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    reviewers:
      - "maintainer-team"
    
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
```

## Best Practices

1. **Branch Protection**: Require PR reviews and passing CI
2. **Automated Testing**: Run tests on every push
3. **Code Coverage**: Maintain >80% coverage
4. **Security Scanning**: Regular dependency and code scanning
5. **Performance Monitoring**: Track benchmarks over time
6. **Semantic Versioning**: Follow semver for releases
7. **Documentation**: Update docs with code changes
8. **Container Security**: Scan images for vulnerabilities

## See Also

- [Contributing Guide](contributing.md)
- [Testing Guide](testing.md)
- [Architecture](architecture.md)
- [Release Process](../RELEASING.md)