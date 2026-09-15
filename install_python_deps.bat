@echo off
setlocal EnableExtensions
cd /d "%~dp0"
if not exist requirements-runtime.lock (
  echo ERROR: requirements-runtime.lock is missing. Extract the complete Feathered source archive.
  pause
  exit /b 1
)
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 -m pip install --disable-pip-version-check --require-hashes --only-binary=:all: -r requirements-runtime.lock
) else (
  python -m pip install --disable-pip-version-check --require-hashes --only-binary=:all: -r requirements-runtime.lock
)
if errorlevel 1 (
  echo.
  echo ERROR: Python dependency installation failed.
  pause
  exit /b 1
)
echo.
echo Dependencies installed successfully.
pause
