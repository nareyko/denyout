@echo off
REM Windows UI entry — double-click after extracting the release zip.
cd /d "%~dp0"
if exist "%~dp0denyout-cli.exe" (
  "%~dp0denyout-cli.exe" desktop --install
) else if exist "%~dp0denyout.exe" (
  start "" "%~dp0denyout.exe" --open
) else (
  echo denyout-cli.exe / denyout.exe not found next to this script.
  echo Extract the full release zip so binaries and Start-DenyOut.cmd are in the same folder.
  pause
)
