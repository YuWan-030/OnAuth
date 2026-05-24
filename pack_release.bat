@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0pack_release.ps1" %*
exit /b %ERRORLEVEL%

