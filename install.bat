@echo off
chcp 65001 >nul
title 42IPwin - 一键安装

echo ==========================================
echo   42IPwin 多IP SOCKS5 代理 - 安装脚本
echo ==========================================
echo.

:: 检查管理员权限
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 请以管理员身份运行此脚本！
    echo 右键 install.bat - 以管理员身份运行
    pause
    exit /b 1
)

cd /d "%~dp0"

:: 1. 创建目录
echo [1/5] 创建目录结构...
if not exist "3proxy" mkdir "3proxy"
if not exist "3proxy\logs" mkdir "3proxy\logs"
if not exist "data" mkdir "data"
if not exist "data\counters" mkdir "data\counters"
echo       完成
echo.

:: 2. 下载 3proxy
echo [2/5] 检查 3proxy.exe...
if not exist "3proxy\3proxy.exe" (
    echo       正在下载 3proxy 0.9.4 ...
    powershell -NoProfile -Command ^
      "try { Invoke-WebRequest -Uri 'https://github.com/3proxy/3proxy/releases/download/0.9.4/3proxy-0.9.4.x86_64.zip' -OutFile '3proxy.zip' -UseBasicParsing; Write-Host '       下载完成' } catch { Write-Host ('       [错误] 下载失败: ' + $_.Exception.Message); exit 1 }"
    if exist "3proxy.zip" (
        echo       解压中...
        powershell -NoProfile -Command "Expand-Archive -Path '3proxy.zip' -DestinationPath '3proxy_tmp' -Force"
        if exist "3proxy_tmp\x86_64\3proxy.exe" (
            move /Y "3proxy_tmp\x86_64\3proxy.exe" "3proxy\3proxy.exe" >nul
        ) else (
            :: 兼容不同压缩包结构
            for /r "3proxy_tmp" %%F in (3proxy.exe) do (
                move /Y "%%F" "3proxy\3proxy.exe" >nul
            )
        )
        rd /s /q "3proxy_tmp"
        del /q "3proxy.zip"
    )
)
if exist "3proxy\3proxy.exe" (
    echo       OK - 3proxy.exe 已就绪
) else (
    echo       [警告] 未找到 3proxy.exe，请手动下载放到 3proxy\ 目录
    echo       下载地址: https://github.com/3proxy/3proxy/releases
)
echo.

:: 3. 检查 Python
echo [3/5] 检查 Python...
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo       [错误] 未检测到 Python，请先安装 Python 3.8+
    echo       下载地址: https://www.python.org/downloads/
    pause
    exit /b 1
)
for /f "delims=" %%V in ('python --version 2^>^&1') do echo       %%V 已安装
echo.

:: 4. 安装依赖
echo [4/5] 安装 Python 依赖...
python -m pip install --upgrade pip -i https://pypi.tuna.tsinghua.edu.cn/simple
python -m pip install -r panel\requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
if %errorlevel% neq 0 (
    echo       [警告] 依赖安装失败，请检查网络
) else (
    echo       完成
)
echo.

:: 5. 初始化数据库
echo [5/5] 初始化数据库...
python panel\app.py --init
echo.

:: 添加防火墙规则
echo [附加] 配置 Windows 防火墙...
netsh advfirewall firewall add rule name="42IPwin SOCKS5 10801" dir=in action=allow protocol=TCP localport=10801 >nul 2>&1
netsh advfirewall firewall add rule name="42IPwin SOCKS5 10802" dir=in action=allow protocol=TCP localport=10802 >nul 2>&1
netsh advfirewall firewall add rule name="42IPwin SOCKS5 10803" dir=in action=allow protocol=TCP localport=10803 >nul 2>&1
netsh advfirewall firewall add rule name="42IPwin Panel 8080" dir=in action=allow protocol=TCP localport=8080 >nul 2>&1
echo       防火墙规则已添加
echo.

echo ==========================================
echo   安装完成！
echo ==========================================
echo.
echo 下一步:
echo   1. 双击 start.bat 启动服务
echo   2. 浏览器打开 http://127.0.0.1:8080
echo   3. 默认账号: admin / admin123 (登录后请立即改密)
echo.
pause
