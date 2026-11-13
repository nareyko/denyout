@echo off
REM Windows UI entry — double-click after extracting the release zip.
cd /d "%~dp0"
if exist "%~dp0denyout.exe" (
  start "" "%~dp0denyout.exe" desktop --setup
) else (
  echo denyout.exe not found next to this script.
  echo Extract the full release zip so denyout.exe and Start-DenyOut.cmd are in the same folder.
  pause
)
