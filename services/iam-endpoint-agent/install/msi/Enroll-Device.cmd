@echo off
rem Registers this laptop with your organisation, then starts the IAM Endpoint Agent service.
rem Opens your browser to sign in with your work account. Needs administrator rights (asks for them).
rem Optional first argument: CORPORATE or BYOD (default BYOD = an administrator must approve the device).
net session >nul 2>&1
if %errorlevel% neq 0 (
  rem Start-Process rejects an empty -ArgumentList, so only pass one when there are arguments.
  if "%~1"=="" (
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
  ) else (
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0' -ArgumentList '%~1'"
  )
  exit /b
)
set OWNERSHIP=%~1
if "%OWNERSHIP%"=="" set OWNERSHIP=BYOD
echo Registering this device. Your browser opens; sign in there. This window continues by itself.
"%~dp0iam-endpoint-agent.exe" --enroll --ownership=%OWNERSHIP%
if %errorlevel% equ 3 goto start
if %errorlevel% neq 0 (
  echo.
  echo Enrollment did not complete. Nothing was started. Close this window and try again.
  pause
  exit /b 1
)
:start
net start IamEndpointAgent
echo.
echo Done. An administrator can now approve this device in the Admin Console under Endpoint Security.
pause
