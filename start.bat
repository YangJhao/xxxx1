@echo off
chcp 65001 >nul
title 42IPwin - 启动服务

cd /d "%~dp0"

echo ==========================================
echo   42IPwin 启动中...
echo ==========================================
echo.

:: 启动后台管理 (会自动启动 3proxy + 流量采集)
echo [1/2] 启动管理后台...
start "42IPwin-Panel" /min cmd /c "python panel\app.py"

timeout /t 3 /nobreak >nul

:: 单独把 3proxy 启起来（如果管理后台未自动起）
echo [2/2] 启动 3proxy 代理服务...
if exist "3proxy\3proxy.exe" (
    if exist "3proxy\3proxy.cfg" (
        start "42IPwin-3proxy" /min "3proxy\3proxy.exe" "3proxy\3proxy.cfg"
        echo       3proxy 已启动
    ) else (
        echo       [提示] 3proxy.cfg 尚未生成，请先访问后台添加线路
    )
) else (
    echo       [错误] 3proxy.exe 不存在，请先运行 install.bat
)

echo.
echo ==========================================
echo   启动完成
echo ==========================================
echo.
echo   管理后台: http://127.0.0.1:8080
echo   SOCKS5   : 公网IP:10801/10802/10803
echo.
echo   默认账号: admin / admin123
echo.
echo 关闭本窗口不会停止服务（最小化运行中）
echo 如需停止，请运行 stop.bat
echo ==========================================
timeout /t 8 /nobreak >nul
