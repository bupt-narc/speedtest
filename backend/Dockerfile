# backend/Dockerfile
FROM golang:1.19-alpine as builder
WORKDIR /app

# 先复制依赖文件并下载
COPY go.mod go.sum ./
RUN go mod download

# 复制所有源码到容器中（包括 cmd 和 pkg 目录）
COPY . .

# 明确指定构建入口文件路径
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '-s -w' -o speedtest ./cmd/main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/speedtest .
EXPOSE 80
CMD ["./speedtest", "--bind-address=0.0.0.0", "--port=80"]
