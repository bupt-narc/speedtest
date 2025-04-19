# 构建阶段
FROM node:16-alpine as builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# 运行阶段
FROM nginx:alpine

# 删除默认配置（重要！否则会与模板生成的文件冲突）
RUN rm /etc/nginx/conf.d/default.conf

# 复制构建产物
COPY --from=builder /app/dist /usr/share/nginx/html

# 关键改动：复制模板文件到专用目录（注意文件名后缀）
COPY nginx.conf.template /etc/nginx/templates/default.conf.template

# 暴露端口（已有配置保持原样）
EXPOSE 80
