@echo off
setlocal EnableExtensions
cd /d "%~dp0"

REM Feathered Windows builder.
REM   build_exe.bat           -> practical local unsigned EXE build
REM   build_exe.bat --release -> fail-closed production release gate
REM Local mode deliberately does not run the entire release certification
REM corpus; release mode remains pinned to CPython 3.13 and the hash lock.

set "RELEASE_MODE=0"
set "BUILD_STEP=argument parsing"
if /I "%~1"=="--release" (
  set "RELEASE_MODE=1"
  shift
)
if not "%~1"=="" (
  echo ERROR: unknown build option: %~1
  echo Usage: build_exe.bat [--release]
  goto :fail
)

set "BUILD_STEP=locating Python"
set "BASE_PY="
if "%RELEASE_MODE%"=="1" (
  REM Production is intentionally fixed to one Python minor for reproducibility.
  REM CI exports FEATHERED_RELEASE_PYTHON after authenticating the full
  REM python.org installer and proving that its Tcl/Tk runtime starts.
  if defined FEATHERED_RELEASE_PYTHON (
    if exist "%FEATHERED_RELEASE_PYTHON%" (
      "%FEATHERED_RELEASE_PYTHON%" -c "import struct,sys; raise SystemExit(0 if sys.version_info[:3]==(3,13,15) and struct.calcsize('P')*8==64 else 1)" >nul 2>nul
      if not errorlevel 1 set "BASE_PY=%FEATHERED_RELEASE_PYTHON%"
    )
  )
  if not defined BASE_PY (
    where py >nul 2>nul
    if not errorlevel 1 (
      py -3.13 -c "import struct,sys; raise SystemExit(0 if sys.version_info[:2]==(3,13) and struct.calcsize('P')*8==64 else 1)" >nul 2>nul
      if not errorlevel 1 set "BASE_PY=py -3.13"
    )
  )
  if not defined BASE_PY (
    where python >nul 2>nul
    if not errorlevel 1 (
      python -c "import struct,sys; raise SystemExit(0 if sys.version_info[:2]==(3,13) and struct.calcsize('P')*8==64 else 1)" >nul 2>nul
      if not errorlevel 1 set "BASE_PY=python"
    )
  )
  if not defined BASE_PY (
    echo ERROR: Production releases require 64-bit CPython 3.13.
    echo        Install Python 3.13 x64 or make it available as py -3.13/python.
    goto :fail
  )
) else (
  REM Local unsigned builds may use supported current CPython minors. Prefer the
  REM newest installed launcher, then fall back to python.exe.
  where py >nul 2>nul
  if not errorlevel 1 (
    py -3.14 -c "import struct,sys; raise SystemExit(0 if sys.version_info[:2]==(3,14) and struct.calcsize('P')*8==64 else 1)" >nul 2>nul
    if not errorlevel 1 set "BASE_PY=py -3.14"
    if not defined BASE_PY (
      py -3.13 -c "import struct,sys; raise SystemExit(0 if sys.version_info[:2]==(3,13) and struct.calcsize('P')*8==64 else 1)" >nul 2>nul
      if not errorlevel 1 set "BASE_PY=py -3.13"
    )
    if not defined BASE_PY (
      py -3.12 -c "import struct,sys; raise SystemExit(0 if sys.version_info[:2]==(3,12) and struct.calcsize('P')*8==64 else 1)" >nul 2>nul
      if not errorlevel 1 set "BASE_PY=py -3.12"
    )
  )
  if not defined BASE_PY (
    where python >nul 2>nul
    if not errorlevel 1 (
      python -c "import struct,sys; ok=((3,12) <= sys.version_info[:2] <= (3,14) and struct.calcsize('P')*8==64); raise SystemExit(0 if ok else 1)" >nul 2>nul
      if not errorlevel 1 set "BASE_PY=python"
    )
  )
  if not defined BASE_PY (
    echo ERROR: Local builds require 64-bit CPython 3.12, 3.13, or 3.14.
    echo        Install a 64-bit python.org build and try again.
    goto :fail
  )
)

%BASE_PY% -c "import struct,sys; print('Using Python', sys.version.split()[0], '('+str(struct.calcsize('P')*8)+'-bit)')"
if errorlevel 1 goto :fail

if "%RELEASE_MODE%"=="1" (
  echo Running SIGNED PRODUCTION RELEASE build.
  if not defined FEATHERED_SIGN_CERT_SHA1 (
    echo ERROR: FEATHERED_SIGN_CERT_SHA1 is required with --release.
    goto :fail
  )
  if not defined FEATHERED_TIMESTAMP_URL (
    echo ERROR: FEATHERED_TIMESTAMP_URL is required with --release.
    goto :fail
  )
  if not defined FEATHERED_SMOKE_ISO (
    echo ERROR: FEATHERED_SMOKE_ISO must point to a real ISO with --release.
    goto :fail
  )
  where signtool.exe >nul 2>nul
  if errorlevel 1 (
    echo ERROR: signtool.exe was not found; it is required with --release.
    goto :fail
  )
) else (
  echo Running LOCAL UNSIGNED build. For a production artifact use: build_exe.bat --release
)

REM A fresh venv prevents an existing site-package from changing the build.
set "BUILD_STEP=creating build virtual environment"
set "BUILD_VENV=%CD%\.release-venv"
if exist "%BUILD_VENV%" rmdir /S /Q "%BUILD_VENV%"
%BASE_PY% -m venv "%BUILD_VENV%"
if errorlevel 1 goto :fail
set "PY=%BUILD_VENV%\Scripts\python.exe"

REM The source-gate venv carries its own Tcl/Tk data so a long multi-process
REM test run never depends on the bootstrap copy under RUNNER_TEMP. Production
REM rebuilds a fresh venv and reruns that corpus, so apply the same rule here.
if not "%RELEASE_MODE%"=="1" goto :after_release_tcl_stage
set "BUILD_STEP=staging Tcl/Tk runtime into build virtual environment"
if not defined TCL_LIBRARY (
  echo ERROR: TCL_LIBRARY was not exported by the authenticated Python bootstrap.
  goto :fail
)
if not defined TK_LIBRARY (
  echo ERROR: TK_LIBRARY was not exported by the authenticated Python bootstrap.
  goto :fail
)
if not exist "%TCL_LIBRARY%\init.tcl" (
  echo ERROR: Tcl runtime is incomplete: %TCL_LIBRARY%\init.tcl
  goto :fail
)
if not exist "%TK_LIBRARY%\tk.tcl" (
  echo ERROR: Tk runtime is incomplete: %TK_LIBRARY%\tk.tcl
  goto :fail
)
for %%I in ("%TCL_LIBRARY%") do set "TCL_DIR_NAME=%%~nxI"
for %%I in ("%TK_LIBRARY%") do set "TK_DIR_NAME=%%~nxI"
for %%I in ("%TCL_LIBRARY%\..") do set "TCL_RUNTIME_ROOT=%%~fI"
if exist "%BUILD_VENV%\tcl" rmdir /S /Q "%BUILD_VENV%\tcl"
mkdir "%BUILD_VENV%\tcl"
if errorlevel 1 goto :fail
xcopy /E /I /Y /Q "%TCL_RUNTIME_ROOT%\*" "%BUILD_VENV%\tcl\" >nul
if errorlevel 1 goto :fail
set "TCL_LIBRARY=%BUILD_VENV%\tcl\%TCL_DIR_NAME%"
set "TK_LIBRARY=%BUILD_VENV%\tcl\%TK_DIR_NAME%"
if not exist "%TCL_LIBRARY%\init.tcl" (
  echo ERROR: Staged Tcl runtime is incomplete: %TCL_LIBRARY%\init.tcl
  goto :fail
)
if not exist "%TK_LIBRARY%\tk.tcl" (
  echo ERROR: Staged Tk runtime is incomplete: %TK_LIBRARY%\tk.tcl
  goto :fail
)
"%PY%" -c "import tkinter as tk; r=tk.Tk(); print('release-build Tcl',r.tk.call('info','patchlevel')); r.destroy()"
if errorlevel 1 goto :fail
:after_release_tcl_stage

set "BUILD_STEP=installing build dependencies"
if "%RELEASE_MODE%"=="1" (
  REM Production inputs are the complete CPython 3.13 / Windows x64 wheel lock.
  "%PY%" -m pip install --disable-pip-version-check --require-hashes --only-binary=:all: -r requirements-build.lock
  if errorlevel 1 goto :fail
  set "FEATHERED_BUILD_MODE=release"
  set "FEATHERED_BUILD_LOCK=requirements-build.lock"
) else (
  REM Local compilation pins the two root packages but lets pip select compatible
  REM transitive wheels for Python 3.12-3.14. This artifact is explicitly unsigned
  REM and is not release evidence.
  "%PY%" -m pip install --disable-pip-version-check --only-binary=:all: "pyinstaller==6.22.3" "zstandard==0.25.0" "PyYAML==6.0.3"
  if errorlevel 1 goto :fail
  set "FEATHERED_BUILD_MODE=local"
  set "FEATHERED_BUILD_LOCK="
)

set "BUILD_STEP=checking all Python source syntax"
"%PY%" check_python_sources.py
if errorlevel 1 goto :fail

if "%RELEASE_MODE%"=="1" (
  set "BUILD_STEP=running complete regression corpus"
  "%PY%" release_test_runner.py
  if errorlevel 1 goto :fail

  REM Production requirement: Feathered's actual _mount_disc_image path must be
  REM exercised on the release builder using a caller-supplied real ISO fixture.
  set "BUILD_STEP=running Windows ISO mount smoke gate"
  powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File windows_release_smoke.ps1 -IsoPath "%FEATHERED_SMOKE_ISO%" -PythonExe "%PY%"
  if errorlevel 1 goto :fail
)

set "BUILD_STEP=preparing distribution directory"
if exist dist rmdir /S /Q dist
mkdir dist
if errorlevel 1 goto :fail

REM Stage the pinned official GnuPG verifier. stage_gpgv.ps1 verifies the exact
REM upstream installer SHA-256 before executing it and chooses a writable,
REM space-free temporary path suitable for NSIS /D=.
set "BUILD_STEP=staging authenticated GnuPG verifier"
powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File stage_gpgv.ps1 -Destination "dist\gnupg"
if errorlevel 1 goto :fail

REM Sign every PE verifier component with the Feathered release identity before
REM hashing it. This makes Windows signature inspection useful in addition to
REM Feathered's exact SHA-256 policy enforcement.
if "%RELEASE_MODE%"=="1" (
  set "BUILD_STEP=signing GnuPG verifier components"
  for %%F in (dist\gnupg\*.exe dist\gnupg\*.dll) do (
    signtool.exe sign /sha1 "%FEATHERED_SIGN_CERT_SHA1%" /fd SHA256 /tr "%FEATHERED_TIMESTAMP_URL%" /td SHA256 "%%F"
    if errorlevel 1 goto :fail
    signtool.exe verify /pa "%%F"
    if errorlevel 1 goto :fail
  )
)

dist\gnupg\gpgv.exe --version > dist\gnupg\VERIFIER-VERSION.txt
if errorlevel 1 goto :fail

REM Generate the exact sidecar hash set after optional signing. The JSON is
REM embedded in Feathered.exe and therefore covered by Authenticode in release mode.
set "BUILD_STEP=generating embedded verifier-integrity policy"
"%PY%" write_verifier_policy.py
if errorlevel 1 goto :fail

set "BUILD_STEP=compiling Feathered.exe with PyInstaller"
"%PY%" -m PyInstaller --clean --noconsole --onefile --name Feathered ^
  --hidden-import zstandard --collect-all zstandard ^
  --add-data "verify_bundle_template.py;." ^
  --add-data "receiver_preflight.py;." ^
  --add-data "k8s_knowledge_seed.json;." ^
  --add-data "verifier-integrity.json;." app.py
if errorlevel 1 goto :fail

set "BUILD_STEP=staging distribution sidecars"
copy /Y workloads.example.json dist\workloads.example.json >nul
if errorlevel 1 goto :fail
copy /Y target_inventory.sh dist\target_inventory.sh >nul
if errorlevel 1 goto :fail
copy /Y target_inventory_details.py dist\target_inventory_details.py >nul
if errorlevel 1 goto :fail
copy /Y trusted_receiver.py dist\trusted_receiver.py >nul
if errorlevel 1 goto :fail
copy /Y LICENSE dist\LICENSE >nul
if errorlevel 1 goto :fail
copy /Y NOTICE.md dist\NOTICE.md >nul
if errorlevel 1 goto :fail
if exist dist\mirror_catalogs rmdir /S /Q dist\mirror_catalogs
xcopy /E /I /Y mirror_catalogs dist\mirror_catalogs >nul
if errorlevel 1 goto :fail

if "%RELEASE_MODE%"=="1" (
  set "BUILD_STEP=signing Feathered.exe"
  signtool.exe sign /sha1 "%FEATHERED_SIGN_CERT_SHA1%" /fd SHA256 /tr "%FEATHERED_TIMESTAMP_URL%" /td SHA256 dist\Feathered.exe
  if errorlevel 1 goto :fail
  signtool.exe verify /pa dist\Feathered.exe
  if errorlevel 1 goto :fail
)

set "BUILD_STEP=writing and verifying distribution checksums"
"%PY%" write_release_manifest.py
if errorlevel 1 goto :fail
"%PY%" verify_release_checksums.py dist
if errorlevel 1 goto :fail

del /Q verifier-integrity.json 2>nul
rmdir /S /Q "%BUILD_VENV%" 2>nul

echo.
echo Build complete: dist\Feathered.exe
if "%RELEASE_MODE%"=="0" echo NOTE: this artifact is unsigned and is NOT a production release.
echo Authenticated OpenPGP verifier: dist\gnupg\
echo External workload template: dist\workloads.example.json
echo Target inventory helper: dist\target_inventory.sh
echo Editable provenance mirror catalogs: dist\mirror_catalogs\
echo Audit manifest: dist\RELEASE-MANIFEST.json
echo Distribution checksums: dist\SHA256SUMS.txt
exit /b 0

:fail
set "RC=%ERRORLEVEL%"
if "%RC%"=="0" set "RC=1"
del /Q verifier-integrity.json 2>nul
if defined BUILD_VENV rmdir /S /Q "%BUILD_VENV%" 2>nul
echo.
echo ERROR: build stopped during: %BUILD_STEP%
if "%RELEASE_MODE%"=="1" (
  echo ERROR: Feathered production build failed a mandatory release gate.
) else (
  echo ERROR: Feathered local EXE build failed.
)
echo ERROR: Re-run build_exe_debug.bat to keep a complete build-exe.log on screen and on disk.
exit /b %RC%
