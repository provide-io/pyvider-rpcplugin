#!/bin/bash

echo "Changing directory to /app and sourcing env.sh..."
cd /app && source env.sh

echo "Running mypy src..."
mypy src

echo "mypy check complete."
