# Chapter 19: Contributing to Pyvider RPCPlugin

Thank you for your interest in contributing to `pyvider.rpcplugin`! We welcome contributions from the community to help improve and evolve the framework.

## How to Contribute

Currently, formal contribution guidelines (like a `CONTRIBUTING.md` file) are yet to be established in detail. However, the general ways to contribute are:

1.  **Reporting Bugs**: If you find a bug, please open an issue on the project's GitHub repository. Include as much detail as possible:
    *   Version of `pyvider.rpcplugin` you are using.
    *   Python version.
    *   Operating system.
    *   A clear description of the bug.
    *   Steps to reproduce the bug.
    *   Any relevant error messages or stack traces.
    *   A minimal, reproducible code example if possible.

2.  **Suggesting Enhancements or New Features**: If you have ideas for new features or improvements to existing ones, please open an issue on GitHub. Describe the feature, its potential benefits, and any proposed implementation ideas.

3.  **Pull Requests**: If you'd like to contribute code:
    *   Please first open an issue to discuss the change you wish to make, especially for larger contributions. This helps ensure your work aligns with the project's goals and avoids duplicated effort.
    *   Fork the repository and create a new branch for your feature or bug fix.
    *   Write clean, well-tested, and well-documented code.
    *   Ensure your changes pass all existing tests (`pytest`).
    *   Add new tests to cover your changes.
    *   Follow existing code style (Ruff is used for formatting and linting).
    *   Update any relevant documentation.
    *   Submit a pull request against the main branch. Provide a clear description of your changes.

## Development Setup

If you plan to contribute code, you'll need to set up a development environment:

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/provide-io/pyvider-rpcplugin.git
    cd pyvider-rpcplugin
    ```

2.  **Install dependencies**: It's highly recommended to use a virtual environment. `uv` is used by this project.
    ```bash
    # Create and activate a virtual environment (example with venv)
    # python -m venv .venv
    # source .venv/bin/activate # or .\.venv\Scripts\activate on Windows

    # Install dependencies including development tools
    uv sync --all-groups
    ```
    This will install `pytest` for testing, `mypy` for type checking, `ruff` for linting/formatting, `grpcio-tools` for protobuf compilation, etc.

3.  **Running Tests**:
    ```bash
    uv run pytest
    ```
    To run tests with coverage:
    ```bash
    uv run pytest --cov=pyvider.rpcplugin --cov-report=html
    ```

4.  **Type Checking**:
    ```bash
    uv run mypy src tests examples
    ```

5.  **Linting and Formatting**:
    ```bash
    uv run ruff check .  # Check for linting issues
    uv run ruff format . # Auto-format code
    ```

## Code of Conduct

While a formal Code of Conduct document might not be in place yet, we expect all contributors and participants to engage in a respectful and constructive manner.

We look forward to your contributions!
