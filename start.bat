@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo 🚀 网速测试应用快速启动...

REM 检查Docker是否运行
docker info >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker未运行，请先启动Docker
    pause
    exit /b 1
)

REM 检查是否已有容器运行
docker ps -q -f name=speedtest >nul 2>&1
if not errorlevel 1 (
    echo ⚠️  检测到已有容器运行，正在停止...
    docker stop speedtest >nul 2>&1
    docker rm speedtest >nul 2>&1
)

REM 检查镜像是否存在
docker images speedtest-app:latest | findstr speedtest-app >nul 2>&1
if errorlevel 1 (
    echo 📦 镜像不存在，正在构建...
    docker build -t speedtest-app:latest .
)

REM 启动容器
echo 🚀 启动容器...
docker run -d --name speedtest -p 8080:8080 --restart unless-stopped --env-file config.env speedtest-app:latest

REM 等待应用启动
echo ⏳ 等待应用启动...
timeout /t 5 /nobreak >nul

REM 检查应用状态
echo 🔍 检查应用状态...
powershell -Command "try { Invoke-WebRequest -Uri 'http://localhost:8080' -UseBasicParsing | Out-Null; exit 0 } catch { exit 1 }"
if errorlevel 0 (
    echo ✅ 应用启动成功!
    echo 🌐 访问地址: http://localhost:8080
    echo.
    echo 📊 容器状态:
    docker ps | findstr speedtest
    echo.
    echo 📝 查看日志: docker logs -f speedtest
    echo ⏹️  停止应用: docker stop speedtest
) else (
    echo ❌ 应用启动失败，请检查日志:
    docker logs speedtest
    pause
    exit /b 1
)

pause
