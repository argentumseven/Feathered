@echo off
setlocal EnableExtensions
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 -m pip install --disable-pip-version-check -r requirements.txt
) else (
  python -m pip install --disable-pip-version-check -r requirements.txt
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
