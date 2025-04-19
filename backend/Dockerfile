
# 构建阶段
FROM golang:1.19-alpine as builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o speedtest .

# 运行阶段
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/speedtest .
EXPOSE 80
CMD ["./speedtest", "ingress", "--bind-address=0.0.0.0", "--port=8081"]
