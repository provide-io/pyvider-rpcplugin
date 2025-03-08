
# Base image with minimal dependencies
FROM debian:bookworm-slim AS base
ENV TERM xterm-256color
ENV PY_COLORS 1

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PATH="/root/.local/bin:$PATH"

# Install required system dependencies
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    gnupg \
    lsb-release \
    openssl \
    procps \
    python3 python3-pip \
  && rm -rf /var/lib/apt/lists/*

# Install uv for Python version and package management
RUN curl -fsSL https://astral.sh/uv/install.sh | sh

RUN uv --version

################################################################################
# === Development Stage ===
FROM base AS development
ENV TERM xterm-256color
ENV PY_COLORS 1

# Install Python dependencies using uv
WORKDIR /pyvider

COPY pyproject.toml .

RUN uv sync --all-groups --dev \
  && uv run python3 -V

# Copy project files
COPY . .

# Set up entrypoint script
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV PYTHONPATH /pyvider:/pyvider/src

RUN find /
ENTRYPOINT ["/entrypoint.sh"]

CMD ["test"]

################################################################################
# === Testing Stage ===
FROM development AS testing
ENV TERM xterm-256color
ENV PY_COLORS 1

# Run tests
ENTRYPOINT ["uv", "sync", "--all-groups", "--dev"]

CMD ["uv", "run", "pytest", "-n", "auto", "--cov", "pyvider.rpclugin", "--color", "yes"]

# === Build Stage ===
FROM development AS build

# Build the package
RUN uv sync --all-groups --dev \
    && uv run hatch build

# Output directory for built packages
VOLUME /dist
CMD cp dist/* /dist/
