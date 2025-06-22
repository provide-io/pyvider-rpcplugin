#!/bin/bash

echo "Changing directory to /app and sourcing env.sh..."
cd /app && source env.sh

echo "Environment variables after sourcing env.sh:"
env

echo "Checking tool versions..."
uv -V
python3 -V

echo "Environment setup complete."
