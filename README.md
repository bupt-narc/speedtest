# Speed Test

简单、开箱即用的网页测速工具。后端使用 Go，前端使用 Vue，静态资源通过 Go embed 打包随二进制发布。本文档仅涵盖本项目的构建、运行与使用说明，不涉及任何反向代理相关操作。

## 特性

- 轻量单一二进制运行
- 提供常用测速端点：下载、上传、IP 查询
- 可选启用 TLS 与（基于 TLS 的）HTTP/2
- 支持通过 `base-url` 自定义挂载路径

## 环境与依赖

- Go（建议 1.20+）
- Node.js（用于前端构建）
- Make（构建与容器打包）

## 构建

构建前端并生成后端二进制：

```shell
make
```

完成后将得到静态可执行文件 `speedtest`（Windows 下为 `speedtest.exe`）。

## 运行

直接启动：

```shell
./speedtest
```

常用参数（全部可选）：

- `--log-level`：日志级别（默认 `info`）
- `--bind-address`：监听地址（默认 `0.0.0.0`）
- `--port`：监听端口（默认 `80`）
- `--base-url`：服务挂载前缀（例如 `/speedtest`，默认空）
- `--http2`：是否启用 HTTP/2（仅在启用 TLS 时生效）
- `--cert-file` / `--key-file`：启用 TLS 所需证书与私钥路径

示例：

```shell
./speedtest --port 8080 --base-url /speedtest
```

应用启动后，前端页面与接口会挂载在 `http://<host>:<port><base-url>/` 下。

## Docker 使用

构建镜像：

```shell
make container
```

运行容器（示例将服务暴露在宿主的 8080 端口）：

```shell
docker run --rm -p 8080:80 vcs.bupt-narc.cn/mtd/speedtest
```

如需自定义端口或 `base-url`，可传入参数：

```shell
docker run --rm -p 8080:8081 vcs.bupt-narc.cn/mtd/speedtest \
  --port 8081 --base-url /speedtest
```

注意：若需要在容器中启用 TLS，请将证书与私钥以卷挂载进容器，并通过 `--cert-file` 与 `--key-file` 指定路径。

## API 终结点

以下路径均会附着在 `base-url` 之后（如果设置了 `--base-url`）：

- `/getIP` 与 `/backend/getIP`：查询客户端 IP
- `/garbage` 与 `/backend/garbage`：返回固定大小的随机数据（下载测速）
- `/empty` 与 `/backend/empty`：接收任意大小上传内容（上传测速）

参数：

- `ckSize`（整型，单位 MB）：用于 `/garbage` 指定返回数据块数量。默认 4，最大值受服务端限制（见代码中的 `MaxChunkSize`）。

## 前端开发

在本地进行前端开发调试：

```shell
cd frontend
npm install
npm run dev
```

构建前端产物（被后端 embed 使用）：

```shell
cd frontend
npm run build
```

## 版本

```shell
./speedtest version
```

## 许可

本项目以 MIT 协议开源（如有变更请以仓库实际 LICENSE 为准）。

