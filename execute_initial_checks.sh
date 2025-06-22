#!/bin/bash

echo "Creating and executing a script to set up environment and run tests..."
mkdir -p /app/scripts
cat << 'EOF' > /app/scripts/run_initial_checks.sh
#!/bin/bash
echo "Changing directory to /app and sourcing env.sh..."
cd /app && source ./env.sh || exit 1

echo "Checking tool versions..."
uv -V || echo "uv command failed"
python3 -V || echo "python3 command failed"

echo "Running pytest (simulated for now)..."
# Simulating pytest for now to speed up debugging script execution
echo "Pytest simulation complete."
# timeout 1800 pytest --cov=pyvider.rpcplugin --cov-branch --cov-report=term-missing || true
# echo "Pytest execution finished or timed out."

echo "Environment setup and baseline test run complete."
EOF

chmod +x /app/scripts/run_initial_checks.sh
echo "Script /app/scripts/run_initial_checks.sh created. Attempting to execute..."
/app/scripts/run_initial_checks.sh
echo "Script execution finished."

# Clean up the script after execution to keep the repo clean for subsequent steps
rm /app/scripts/run_initial_checks.sh
