@echo off
setlocal
cd /d "%~dp0"

where go >nul 2>nul
if %errorlevel%==0 (
    echo [Go detected] Building standalone Go Windows SCIM 2.0 Proxy Agent ^(scim-agent.exe^)...
    set CGO_ENABLED=0
    set GOOS=windows
    set GOARCH=amd64
    go build -trimpath -ldflags="-s -w" -o scim-agent.exe .
    if errorlevel 1 (
        echo Go build failed.
        exit /b 1
    )
    echo Built scim-agent.exe via Go successfully!
    exit /b 0
)

set CSC_EXE=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC_EXE%" set CSC_EXE=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe

if exist "%CSC_EXE%" (
    echo [No Go installed — using built-in Windows compiler %CSC_EXE%]
    "%CSC_EXE%" /nologo /optimize+ /target:exe /out:scim-agent.exe ^
        /r:System.dll /r:System.Core.dll /r:System.ServiceProcess.dll ^
        /r:System.Configuration.Install.dll /r:System.Web.Extensions.dll ^
        win-builtin-fallback\ScimAgent.cs
    if errorlevel 1 (
        echo Built-in Windows compilation failed.
        exit /b 1
    )
    echo Built scim-agent.exe natively using built-in Windows compiler ^(zero external installs required^)!
    exit /b 0
)

echo Error: Neither Go nor built-in Windows compiler was found.
exit /b 1
