# ===== Stage 1: Build =====
FROM node:20-alpine AS build
WORKDIR /app

# 先复制依赖清单，利用缓存
COPY package*.json tsconfig.json ./
RUN npm ci

# 复制源码并编译
COPY src ./src
RUN npm run build

# ===== Stage 2: Runtime =====
FROM node:20-alpine
WORKDIR /app

# 仅复制运行所需文件
COPY --from=build /app/dist ./dist
COPY package*.json ./
RUN npm ci --omit=dev

# 设置生产环境变量
ENV NODE_ENV=production

# 暴露 Stratum 端口（可在 .env 中配置）
EXPOSE 3333

# 默认启动命令
CMD ["node", "dist/index.js"]
