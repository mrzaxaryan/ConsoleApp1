@echo off
REM Check if argument is provided
if "%~1"=="" (
    echo Usage: %~n0 file.c
    exit /b
)

REM Input source file
set SRC=%~1
set BIN_DIR=bin

REM Always delete and recreate bin folder
if exist "%BIN_DIR%" rmdir /s /q "%BIN_DIR%"
mkdir "%BIN_DIR%"

REM Output object and binary files
set OBJ=%BIN_DIR%\%~n1.o
set OUTPUT=%BIN_DIR%\%~n1.bin

REM Compile to object file
gcc -c "%SRC%" -o "%OBJ%"

REM Extract .text section from object file
objcopy -O binary -j .text "%OBJ%" "%OUTPUT%"

REM Parse the file and convert to string format
python parser.py "%OUTPUT%"

echo Extracted .text section to: %OUTPUT%
