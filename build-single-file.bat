@echo off
echo ============================================
echo   Building CertDecipher Single-File EXE
echo ============================================
echo.

dotnet publish -c Release -r win-x64

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ============================================
    echo   SUCCESS!
    echo ============================================
    echo.
    echo Your single-file EXE is ready at:
    echo   bin\Release\net8.0-windows\win-x64\publish\CertDecipher.exe
    echo.
    echo File size:
    dir "bin\Release\net8.0-windows\win-x64\publish\CertDecipher.exe" | find "CertDecipher.exe"
    echo.
    start "" "bin\Release\net8.0-windows\win-x64\publish"
) else (
    echo.
    echo ============================================
    echo   BUILD FAILED!
    echo ============================================
    echo.
)

pause
