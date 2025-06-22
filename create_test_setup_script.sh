#!/bin/bash

echo "Creating a script to set up environment and run tests..."
mkdir -p /app/scripts
cat << 'EOF' > /app/scripts/run_initial_checks.sh
#!/bin/bash
echo "Changing directory to /app and sourcing env.sh..."
cd /app && source env.sh

echo "Running pytest with a timeout..."
timeout 1800 pytest --cov=pyvider.rpcplugin --cov-branch --cov-report=term-missing || true
echo "Pytest execution finished or timed out."

echo "Checking tool versions..."
uv -V
python3 -V
echo "Environment setup and baseline test run complete."
EOF

chmod +x /app/scripts/run_initial_checks.sh
echo "Script /app/scripts/run_initial_checks.sh created successfully."
ls -l /app/scripts/run_initial_checks.sh
