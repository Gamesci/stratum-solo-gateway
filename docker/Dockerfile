# ===== 依赖构建阶段 =====
FROM node:20-alpine AS deps
WORKDIR /app

# 安装构建依赖（支持从 Git 拉包）
RUN apk add --no-cache git python3 make g++

# 复制依赖清单
COPY package.json package-lock.json* ./

# 如果有 lock 文件就用 npm ci，否则用 npm install
RUN if [ -f package-lock.json ]; then \
      npm ci --omit=dev; \
    else \
      npm install --omit=dev; \
    fi

# ===== 构建阶段 =====
FROM node:20-alpine AS build
WORKDIR /app

# 安装构建依赖（tsc 等）
RUN apk add --no-cache git python3 make g++

# 复制生产依赖
COPY --from=deps /app/node_modules ./node_modules
COPY package.json package-lock.json* ./

# 安装 devDependencies（typescript、ts-node 等）
RUN if [ -f package-lock.json ]; then \
      npm ci --only=dev; \
    else \
      npm install --only=dev; \
    fi

# 复制源码并编译
COPY . .
RUN npm run build

# ===== 运行阶段 =====
FROM node:20-alpine AS runtime
WORKDIR /app

# 使用 tini 作为 init 进程
RUN apk add --no-cache tini

# 复制运行所需文件
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY --from=deps /app/node_modules ./node_modules

# 创建非 root 用户运行
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

EXPOSE 3333
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/index.js"]
