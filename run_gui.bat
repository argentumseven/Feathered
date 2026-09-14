@echo off
setlocal EnableExtensions

rem All source files must be extracted together, preserving subfolders.
if not exist "%~dp0app.py" goto incomplete
if not exist "%~dp0feathered_app\__init__.py" goto incomplete
if not exist "%~dp0feathered_app\context.py" goto incomplete
if not exist "%~dp0requirements.txt" goto incomplete

pushd "%~dp0"
if errorlevel 1 (
  echo ERROR: Could not open the Feathered application folder.
  pause
  exit /b 1
)

where py >nul 2>nul
if errorlevel 1 (
  where python >nul 2>nul
  if errorlevel 1 (
    echo ERROR: Python 3 was not found. Install Python 3 and rerun.
    popd
    pause
    exit /b 1
  )
  set "PY=python"
) else (
  set "PY=py -3"
)

%PY% -c "import zstandard, yaml" >nul 2>nul
if errorlevel 1 (
  echo Installing required Python dependencies...
  %PY% -m pip install --disable-pip-version-check -r "%~dp0requirements.txt"
  if errorlevel 1 (
    echo ERROR: Could not install Python dependencies.
    popd
    pause
    exit /b 1
  )
)

%PY% "%~dp0app.py"
set "FEATHERED_EXIT=%errorlevel%"
popd
if not "%FEATHERED_EXIT%"=="0" pause
exit /b %FEATHERED_EXIT%

:incomplete
echo ERROR: The Feathered source folder is incomplete.
echo Use Extract All on the ZIP, then open the extracted Feathered_1.3.0 folder.
echo Keep app.py, run_gui.bat, requirements.txt and the entire feathered_app folder together.
pause
exit /b 1
