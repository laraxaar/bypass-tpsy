@echo off
echo [*] Building Bypass TSPU...

:: Check for cl.exe
where cl.exe >nul 2>nul
if %errorlevel% neq 0 (
    echo [!] Error: MSVC compiler (cl.exe) not found. 
    echo Please run this from a Developer Command Prompt for Visual Studio.
    pause
    exit /b
)

:: Compile the project
cl.exe /EHsc /Iinclude src\*.cpp /link ws2_32.lib fwpuclnt.lib /out:bypass_tpsy.exe

if %errorlevel% equ 0 (
    echo [+] Build successful! bypass_tpsy.exe created.
) else (
    echo [-] Build failed.
)

pause
