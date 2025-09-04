# 使用多阶段构建以减少最终镜像大小
FROM node:20-alpine AS builder

# 安装构建依赖
RUN apk add --no-cache git python3 make g++

# 设置工作目录
WORKDIR /app

# 复制 package.json 和 package-lock.json
COPY package*.json ./

# 使用 npm ci 而不是 npm install 以确保依赖一致性
RUN npm ci --only=production

# 复制源代码
COPY . .

# 构建项目
RUN npm run build

# 最终阶段
FROM node:20-alpine

# 安装运行时依赖（如需要）
RUN apk add --no-cache tini

# 设置工作目录
WORKDIR /app

# 从构建阶段复制必要的文件
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist

# 创建非root用户运行应用
RUN addgroup -g 1001 -S nodejs && \
    adduser -S bitcoin -u 1001 && \
    chown -R bitcoin:nodejs /app

# 切换到非root用户
USER bitcoin

# 使用tini作为初始化进程来处理信号
ENTRYPOINT ["/sbin/tini", "--"]

# 暴露Stratum端口
EXPOSE 3333

# 启动应用
CMD ["node", "dist/index.js"]
