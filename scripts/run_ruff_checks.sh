#!/bin/bash

echo "Changing directory to /app and sourcing env.sh..."
cd /app && source env.sh

echo "Running ruff check src..."
ruff check src

echo "ruff check complete."
