#!/bin/bash

# 网速测试应用快速启动脚本

set -e

echo "🚀 网速测试应用快速启动..."

# 检查Docker是否运行
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker未运行，请先启动Docker"
    exit 1
fi

# 检查是否已有容器运行
if docker ps -q -f name=speedtest | grep -q .; then
    echo "⚠️  检测到已有容器运行，正在停止..."
    docker stop speedtest > /dev/null 2>&1 || true
    docker rm speedtest > /dev/null 2>&1 || true
fi

# 检查镜像是否存在
if ! docker images speedtest-app:latest | grep -q speedtest-app; then
    echo "📦 镜像不存在，正在构建..."
    docker build -t speedtest-app:latest .
fi

# 启动容器
echo "🚀 启动容器..."
docker run -d \
    --name speedtest \
    -p 8080:8080 \
    --restart unless-stopped \
    --env-file config.env \
    speedtest-app:latest

# 等待应用启动
echo "⏳ 等待应用启动..."
sleep 5

# 检查应用状态
if curl -s http://localhost:8080 > /dev/null; then
    echo "✅ 应用启动成功!"
    echo "🌐 访问地址: http://localhost:8080"
    echo ""
    echo "📊 容器状态:"
    docker ps | grep speedtest
    echo ""
    echo "📝 查看日志: docker logs -f speedtest"
    echo "⏹️  停止应用: docker stop speedtest"
else
    echo "❌ 应用启动失败，请检查日志:"
    docker logs speedtest
    exit 1
fi
