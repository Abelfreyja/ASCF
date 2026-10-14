@echo off
setlocal
where cl >nul 2>&1
if errorlevel 1 (
    echo Use an x64 Visual Studio developer command prompt.
    exit /b 1
)
if /i not "%VSCMD_ARG_TGT_ARCH%"=="x64" (
    echo This script requires the x64 compiler.
    exit /b 1
)
set "AscfNativeOutput=%~dp0..\src\ASCF\runtimes\win-x64\native"
set "AscfNativeTemp=%TEMP%\ASCF-native-%RANDOM%-%RANDOM%"
mkdir "%AscfNativeTemp%" || exit /b 1
if not exist "%AscfNativeOutput%" mkdir "%AscfNativeOutput%"
pushd "%AscfNativeTemp%" || exit /b 1
cl /nologo /O2 /MT /LD /DLZ4_DLL_EXPORT=1 "%~dp0lz4\lz4.c" "%~dp0lz4\lz4hc.c" /link /Brepro /OUT:"%AscfNativeOutput%\ascf_lz4_v1_10_0.dll"
set "AscfNativeResult=%ERRORLEVEL%"
popd
exit /b %AscfNativeResult%
