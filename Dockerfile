# 多阶段构建Dockerfile
# 第一阶段：构建前端
FROM node:18-alpine AS frontend-builder

WORKDIR /app/frontend

# 复制前端依赖文件
COPY frontend/package*.json ./

# 安装依赖（包含开发依赖以支持 run-p、vite、vue-tsc 等）
RUN npm ci

# 复制前端源代码
COPY frontend/ ./

# 构建前端
RUN npm run build:embed

# 第二阶段：构建Go后端
FROM golang:1.21-alpine AS go-builder

WORKDIR /app

# 安装必要的构建工具
RUN apk add --no-cache git ca-certificates tzdata

# 复制Go模块文件
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 复制前端构建产物到嵌入目录
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# 构建Go应用
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o speedtest ./bin/main.go

# 第三阶段：最终运行镜像
FROM alpine:latest

# 安装必要的运行时依赖
RUN apk --no-cache add ca-certificates tzdata

# 创建非root用户
RUN addgroup -g 1001 -S speedtest && \
    adduser -u 1001 -S speedtest -G speedtest

WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=go-builder /app/speedtest .

# 设置权限
RUN chown -R speedtest:speedtest /app

# 切换到非root用户
USER speedtest

# 暴露端口
EXPOSE 8080

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

# 启动应用
ENTRYPOINT ["./speedtest"]
CMD []
