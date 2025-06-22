#!/bin/bash

echo "Changing directory to /app and sourcing env.sh..."
cd /app && source env.sh

echo "Running bandit -r src..."
bandit -r src

echo "bandit check complete."
