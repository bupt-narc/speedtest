# 容器化变更说明（Speedtest 项目）

本文件记录为实现"一容器启动（前后端一体化）"所做的全部变更，便于后续审计与维护。

## 一、总体目标
- 前端（Vue3+Vite）构建产物通过 Go `embed` 嵌入后端二进制。
- 使用多阶段 Docker 构建，生成单一运行容器（非 root 用户，包含健康检查）。
- 提供一键构建与启动脚本，标准化运行流程（Windows 与 Linux/macOS）。

## 二、修改与新增文件清单

### 2.1 修改的文件
1) `frontend/vite.config.ts`
   - 新增构建输出配置：
     - `build.outDir = '../frontend/dist'`
     - `build.emptyOutDir = true`
     - 保证前端产物输出到 Go `//go:embed frontend/dist` 对应目录。

2) `frontend/package.json`
   - 新增脚本：
     - `"build:embed": "npm run build && echo 'Frontend built for Go embedding'"`
   - 说明：容器内构建会调用此脚本。

3) `frontend/src/App.vue`
   - 修复 TypeScript 类型问题，保证 `vue-tsc` 通过：
     - 为流读取逻辑增加 `response.body` 空值判断。
     - `processData` 增加类型：`ReadableStreamReadResult<Uint8Array>`。
     - 去除 `return reader.read().then(...)` 返回值，避免 `Promise<void>` 与 `void` 冲突。

4) `options.go`
   - 新增 `WithEnvironment()` 方法，支持从环境变量读取配置：
     - `BIND_ADDRESS`、`PORT`、`LOG_LEVEL`、`BASE_URL`
     - `ENABLE_TLS`、`ENABLE_HTTP2`、`TLS_CERT_FILE`、`TLS_KEY_FILE`
   - 配置优先级：命令行参数 > 环境变量 > 默认值

5) `cli.go`
   - 在配置初始化链中增加 `WithEnvironment()` 调用

6) `Dockerfile`
   - 重写为多阶段构建：
     - 阶段一（Node 18 alpine）：`npm ci` 安装包含 devDependencies 的依赖，执行 `npm run build:embed`。
     - 阶段二（Go 1.21 alpine）：复制前端产物到 `./frontend/dist`，`go build` 生成二进制。
     - 阶段三（Alpine 运行时）：非 root 用户运行；`EXPOSE 8080`；健康检查；`ENTRYPOINT ./speedtest`。

7) `Makefile`
   - 统一本地构建与容器构建命令：
     - `build`（先前端，再后端）、`docker-build`、`docker-run`、`docker-stop`、`docker-logs`、`all` 等。

### 2.2 新增的文件
- `.dockerignore`：排除 `frontend/node_modules`、`frontend/dist`、IDE/临时文件等，缩小构建上下文。
- `docker-compose.yml`：本地编排与健康检查配置，支持环境变量文件。
- `build.sh` / `build.bat`：镜像构建脚本。
- `start.sh` / `start.bat`：一键启动脚本（镜像不存在会自动构建，启动后做可用性校验），支持环境变量文件。
- `DOCKER_README.md`：Docker 使用详解与故障排除。
- `env.example`：环境变量示例（绑定地址/端口/TLS/日志/性能/CORS）。
- 本文件：`CHANGES_CONTAINERIZATION.md`。

## 三、关键技术点与原因
- 使用 Go `//go:embed frontend/dist`：避免运行时挂载静态目录，提高可移植性。
- 多阶段 Docker：将构建与运行环境解耦，减小最终镜像体积。
- 前端阶段使用 `npm ci`（而非 `--only=production`）：保证 `npm-run-all2`、`vite`、`vue-tsc` 等 devDependencies 在容器内可用，修复 `run-p: not found`。
- 运行镜像使用非 root 用户、健康检查与端口暴露，满足生产基本要求。

## 四、标准化运行方式

### 4.1 本地（不使用 Docker）
1) 前端构建
```
cd frontend
npm ci
npm run build
cd ..
```
2) 启动后端
```
go run ./bin/main.go --port 8080
```
访问：`http://localhost:8080`

### 4.2 Docker（推荐）
- 一键启动（Windows）：双击 `start.bat`
- 一键启动（Linux/macOS）：
```
./start.sh
```
- 手动：
```
docker build -t speedtest-app:latest .
docker run -d --name speedtest -p 8080:8080 --restart unless-stopped speedtest-app:latest
```
- Compose：
```
docker-compose up -d
```

## 五、兼容性与注意事项
- 如果镜像拉取缓慢，可配置 Docker 国内加速器，或将基础镜像替换为阿里云镜像：
  - `registry.cn-hangzhou.aliyuncs.com/library/node:18-alpine`
  - `registry.cn-hangzhou.aliyuncs.com/library/golang:1.21-alpine`
  - `registry.cn-hangzhou.aliyuncs.com/library/alpine:latest`
- 如需修改服务端口，请调整：
  - 运行参数：`--port`（默认 8080）
  - `Dockerfile` 中的 `EXPOSE` 与 `docker-compose.yml` 的端口映射。
- 修改前端代码后需重新构建并重打镜像，以更新嵌入资源。

## 六、回滚指引
- 将 `Dockerfile`、`Makefile`、脚本与新增文档删除或还原至容器化前版本。
- 将 `frontend/vite.config.ts` 的 `build` 配置移除或改回默认输出目录。
- 将 `frontend/src/App.vue` 中类型修复保留（建议），不影响非容器化运行。

## 七、变更验证
- 前端构建通过（`vue-tsc` 零错误；`vite build` 产物存在于 `frontend/dist`）。
- 后端可本地启动并访问 `http://localhost:8080`。
- Docker 构建成功，容器健康检查通过，页面与接口可正常访问。

---
如需进一步对齐团队发布规范（版本号、签名、CI/CD 流水线集成），可在此文件基础上追加"版本历史""发布流程"等章节。
