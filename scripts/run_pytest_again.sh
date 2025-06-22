#!/bin/bash

echo "Changing directory to /app and sourcing env.sh..."
cd /app && source env.sh

echo "Running pytest again..."
timeout 1800 pytest --cov=pyvider.rpcplugin --cov-branch --cov-report=term-missing || true
echo "Pytest execution finished or timed out."
