# ===== 依赖构建阶段 =====
FROM node:20-alpine AS deps
WORKDIR /app

RUN apk add --no-cache git python3 make g++

COPY package.json package-lock.json* ./

# 安装生产依赖
RUN if [ -f package-lock.json ]; then \
      npm ci --omit=dev; \
    else \
      npm install --omit=dev; \
    fi

# ===== 构建阶段 =====
FROM node:20-alpine AS build
WORKDIR /app

RUN apk add --no-cache git python3 make g++

COPY --from=deps /app/node_modules ./node_modules
COPY package.json package-lock.json* ./

# 安装开发依赖（新版 npm 用 --include=dev）
RUN npm install -g npm@latest \
 && if [ -f package-lock.json ]; then \
      npm ci --include=dev; \
    else \
      npm install --include=dev; \
    fi \
 && npm audit fix || true

COPY . .
RUN npm run build

# ===== 运行阶段 =====
FROM node:20-alpine AS runtime
WORKDIR /app

RUN apk add --no-cache tini

COPY --from=build /app/dist ./dist
COPY package.json ./
COPY --from=deps /app/node_modules ./node_modules

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

EXPOSE 3333
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/index.js"]
