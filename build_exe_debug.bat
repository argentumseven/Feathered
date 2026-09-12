@echo off
setlocal EnableExtensions
cd /d "%~dp0"
del /Q build-exe.log 2>nul
echo Running Feathered EXE build. Output is also saved to build-exe.log.
echo.
call "%~dp0build_exe.bat" %* > "%~dp0build-exe.log" 2>&1
set "RC=%ERRORLEVEL%"
type "%~dp0build-exe.log"
echo.
if "%RC%"=="0" (
  echo SUCCESS. See dist\Feathered.exe
) else (
  echo FAILED with exit code %RC%. Send build-exe.log if diagnosis is needed.
)
pause
exit /b %RC%
