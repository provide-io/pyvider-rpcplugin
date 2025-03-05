
# Dockerfile

FROM python:3.13-slim AS base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PYTHONPATH=/app

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    gnupg \
    lsb-release \
    openssl \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install Go
RUN curl -sL https://golang.org/dl/go1.22.1.linux-amd64.tar.gz | tar -C /usr/local -xzf - \
    && echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile \
    && echo 'export PATH=$PATH:/usr/local/go/bin' >> /root/.bashrc

ENV PATH=$PATH:/usr/local/go/bin

# Verify Go installation
RUN go version

# Set up Python environment
COPY requirements*.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && if [ -f requirements-dev.txt ]; then pip install --no-cache-dir -r requirements-dev.txt; fi

# Install testing tools
RUN pip install --no-cache-dir pytest pytest-asyncio hypothesis behave mypy

# === Development Stage ===
FROM base AS development

# Install development tools
RUN pip install --no-cache-dir black isort flake8 pylint

# Add Terraform
RUN curl -fsSL https://apt.releases.hashicorp.com/gpg | apt-key add - \
    && echo "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main" > /etc/apt/sources.list.d/hashicorp.list \
    && apt-get update \
    && apt-get install -y terraform \
    && rm -rf /var/lib/apt/lists/*

# Add development utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    vim \
    netcat-openbsd \
    strace \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Set up project structure
COPY . .

# Set up entry point script
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["test"]

# === Testing Stage ===
FROM base AS testing

# Copy source code
COPY . .

# Run tests
ENTRYPOINT ["pytest", "-xvs"]

# === Build Stage ===
FROM base AS build

# Copy source code
COPY . .

# Build wheel
RUN pip install --no-cache-dir build \
    && python -m build

# Output directory for built packages
VOLUME /dist
CMD cp dist/* /dist/