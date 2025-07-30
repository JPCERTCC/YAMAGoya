@echo off
setlocal EnableDelayedExpansion

echo YAMAGoya Startup Registration Utility
echo ====================================
echo.
echo This utility will install YAMAGoya to %APPDATA% and register it to start automatically at Windows startup.
echo.
echo 1: Register for current user only
echo 2: Register for all users (requires administrator privileges)
echo 3: Exit
echo.

:MENU
set /p CHOICE=Please select an option (1-3): 

if "%CHOICE%"=="1" goto CURRENT_USER_REGISTRY
if "%CHOICE%"=="2" goto ALL_USERS_REGISTRY
if "%CHOICE%"=="3" goto END

echo Invalid selection. Please try again.
goto MENU

:CURRENT_USER_REGISTRY
echo Installing YAMAGoya to %APPDATA%...
set "INSTALL_DIR=%APPDATA%\YAMAGoya"

call :INSTALL_FILES
if %ERRORLEVEL% NEQ 0 goto END

echo Registering YAMAGoya in registry for current user...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "YAMAGoya" /t REG_SZ /d "%INSTALL_DIR%\YAMAGoya.exe --session --all --detect Rules --verbose" /f
if %ERRORLEVEL% EQU 0 (
    echo Success! YAMAGoya will start automatically at next login.
) else (
    echo Error: Failed to write to registry.
)
goto END

:ALL_USERS_REGISTRY
echo Installing YAMAGoya to %APPDATA%...
set "INSTALL_DIR=%APPDATA%\YAMAGoya"

call :INSTALL_FILES
if %ERRORLEVEL% NEQ 0 goto END

echo Registering YAMAGoya in registry for all users...
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "YAMAGoya" /t REG_SZ /d "%INSTALL_DIR%\YAMAGoya.exe --session --all --detect Rules --verbose" /f
if %ERRORLEVEL% EQU 0 (
    echo Success! YAMAGoya will start automatically at next login for all users.
) else (
    echo Error: Failed to write to registry.
    echo Administrator privileges may be required.
)
goto END

:INSTALL_FILES
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if %ERRORLEVEL% NEQ 0 (
    echo Error: Failed to create installation directory.
    exit /b 1
)

echo Copying YAMAGoya files...
set "FILES_TO_COPY=D3DCompiler_47_cor3.dll PenImc_cor3.dll PresentationNative_cor3.dll vcruntime140_cor3.dll wpfgfx_cor3.dll Yama.dll YAMAGoya.exe"

for %%F in (%FILES_TO_COPY%) do (
    if exist "%~dp0%%F" (
        copy /Y "%~dp0%%F" "%INSTALL_DIR%"
        if %ERRORLEVEL% NEQ 0 (
            echo Error: Failed to copy %%F to installation directory.
            exit /b 1
        )
        echo Copied: %%F
    ) else (
        echo Warning: %%F not found in source directory.
    )
)

echo Copying Rules folder...
if exist "%~dp0rules" (
    xcopy /E /I /Y "%~dp0rules" "%INSTALL_DIR%\Rules"
    if %ERRORLEVEL% NEQ 0 (
        echo Error: Failed to copy rules folder to installation directory.
        exit /b 1
    )
    echo Copied: rules folder
) else (
    echo Warning: rules folder not found in source directory.
    echo Creating empty Rules directory...
    if not exist "%INSTALL_DIR%\Rules" mkdir "%INSTALL_DIR%\Rules"
    if %ERRORLEVEL% NEQ 0 (
        echo Error: Failed to create Rules directory.
        exit /b 1
    )
)

echo YAMAGoya has been installed to: %INSTALL_DIR%
exit /b 0

:END
echo.
echo Press any key to exit...
pause > nul
endlocal
