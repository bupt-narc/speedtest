@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo 🚀 开始构建网速测试应用...

REM 检查Docker是否运行
docker info >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker未运行，请先启动Docker
    pause
    exit /b 1
)

REM 设置镜像名称和标签
set IMAGE_NAME=speedtest-app
set TAG=latest
set FULL_IMAGE_NAME=%IMAGE_NAME%:%TAG%

echo 📦 构建镜像: %FULL_IMAGE_NAME%

REM 构建Docker镜像
docker build -t %FULL_IMAGE_NAME% .

if errorlevel 0 (
    echo ✅ 镜像构建成功!
    
    echo 📊 镜像信息:
    docker images %FULL_IMAGE_NAME%
    
    echo.
    echo 🎯 使用方法:
    echo   1. 直接运行: docker run -p 8080:8080 %FULL_IMAGE_NAME%
    echo   2. 使用docker-compose: docker-compose up -d
    echo   3. 访问应用: http://localhost:8080
    
) else (
    echo ❌ 镜像构建失败!
    pause
    exit /b 1
)

pause
