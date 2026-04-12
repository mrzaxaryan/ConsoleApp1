@echo off
REM Build using MSVC (cl.exe). Requires running from a Developer Command Prompt
REM or having vcvars64.bat already sourced.

cl /nologo /W3 /O2 /Zi ^
   main.c veh.c emulator.c ^
   /Fe:NoRWX.exe ^
   /link /SUBSYSTEM:CONSOLE

if %ERRORLEVEL% neq 0 (
    echo Build failed.
    exit /b 1
)
echo Build succeeded: NoRWX.exe
