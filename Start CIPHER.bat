@echo off
setlocal

rem Resolve the project directory reliably regardless of where this
rem file was double-clicked from (%~dp0 is this .bat's own directory,
rem always ending in a backslash) -- CIPHER's data/keys/logs/reports
rem paths are resolved relative to this directory.
cd /d "%~dp0"

rem Prefer a project virtual environment if one exists in the expected
rem location (.venv\ or venv\ at the project root); otherwise fall
rem back to whatever "python" is available on PATH. Never assumes an
rem activation script has already been run.
set "PYTHON_EXE="
if exist "%~dp0.venv\Scripts\python.exe" set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"
if not defined PYTHON_EXE if exist "%~dp0venv\Scripts\python.exe" set "PYTHON_EXE=%~dp0venv\Scripts\python.exe"
if not defined PYTHON_EXE set "PYTHON_EXE=python"

echo Using Python: %PYTHON_EXE%
echo.

rem launch_cipher.py runs the preflight check, starts run_demo.py,
rem waits for a real HTTP 200 from /api/health, and only then opens
rem the browser. Its own stdout/stderr (and run_demo.py's) print
rem directly into THIS window -- nothing is hidden in the background,
rem so a startup failure stays visible right here.
"%PYTHON_EXE%" launch_cipher.py
set "EXIT_CODE=%ERRORLEVEL%"

echo.
if not "%EXIT_CODE%"=="0" (
    echo CIPHER exited with an error ^(code %EXIT_CODE%^). See the messages above.
) else (
    echo CIPHER has stopped.
)
echo.
echo Press any key to close this window...
pause >nul

endlocal
exit /b %EXIT_CODE%
