@echo off
chcp 65001 >nul
title 42IPwin - 停止服务

echo 正在停止 42IPwin 服务...

:: 停止 3proxy
taskkill /F /IM 3proxy.exe >nul 2>&1
echo [1/2] 3proxy 已停止

:: 停止管理后台
taskkill /F /FI "WINDOWTITLE eq 42IPwin*" >nul 2>&1
:: 上面方式不一定可靠，用 python 进程名兜底
wmic process where "name='python.exe' and commandline like '%%panel%%app.py%%'" delete >nul 2>&1
echo [2/2] 管理后台已停止

echo.
echo 全部服务已停止。
timeout /t 3 /nobreak >nul
