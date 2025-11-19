#!/bin/bash

# 网速测试应用Docker构建脚本

set -e

echo "🚀 开始构建网速测试应用..."

# 检查Docker是否运行
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker未运行，请先启动Docker"
    exit 1
fi

# 设置镜像名称和标签
IMAGE_NAME="speedtest-app"
TAG="latest"
FULL_IMAGE_NAME="${IMAGE_NAME}:${TAG}"

echo "📦 构建镜像: ${FULL_IMAGE_NAME}"

# 构建Docker镜像
docker build -t ${FULL_IMAGE_NAME} .

if [ $? -eq 0 ]; then
    echo "✅ 镜像构建成功!"
    
    # 显示镜像信息
    echo "📊 镜像信息:"
    docker images ${FULL_IMAGE_NAME}
    
    echo ""
    echo "🎯 使用方法:"
    echo "  1. 直接运行: docker run -p 8080:8080 ${FULL_IMAGE_NAME}"
    echo "  2. 使用docker-compose: docker-compose up -d"
    echo "  3. 访问应用: http://localhost:8080"
    
else
    echo "❌ 镜像构建失败!"
    exit 1
fi
