@echo off
REM env.cmd
REM Windows equivalent of env.sh for pyvider-rpcplugin
REM Sets up the development environment using uv

echo 🔧 Setting up Windows development environment for pyvider-rpcplugin...

REM Check if uv is installed
where uv >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo 🚀 Installing uv...
    powershell -Command "irm https://astral.sh/uv/install.ps1 | iex"
    if %ERRORLEVEL% neq 0 (
        echo ❌ Failed to install uv
        exit /b 1
    )
)

echo ✅ uv is available: 
uv --version

echo 🐍 Setting up Python virtual environment...
uv venv

echo 📦 Syncing dependencies...
uv sync --all-groups --dev

echo 🔗 Setting up Python path...
set PYTHONPATH=%CD%\src;%CD%
echo PYTHONPATH=%PYTHONPATH%

echo 📝 Creating activation script...
echo @echo off > activate_env.cmd
echo set PYTHONPATH=%CD%\src;%CD% >> activate_env.cmd
echo call .venv\Scripts\activate.bat >> activate_env.cmd

echo ✅ Environment setup complete!
echo 💡 To activate the environment, run: activate_env.cmd
echo 💡 To run commands directly: uv run ^<command^>

REM Test basic import
echo 🧪 Testing basic import...
uv run python -c "import pyvider.rpcplugin; print('✅ Basic import successful')"

if %ERRORLEVEL% neq 0 (
    echo ⚠️ Basic import test failed - this may be expected in initial setup
)

echo 🎉 Windows environment setup completed!
