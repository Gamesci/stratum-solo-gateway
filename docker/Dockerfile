FROM node:20-alpine

# 安装构建依赖
RUN apk add --no-cache git python3 make g++

WORKDIR /app

# 复制项目文件
COPY . .

# 安装依赖并构建
RUN npm install && npm run build

# 创建非root用户
RUN addgroup -g 1001 -S nodejs && \
    adduser -S bitcoin -u 1001 && \
    chown -R bitcoin:nodejs /app

USER bitcoin

EXPOSE 3333

CMD ["node", "dist/index.js"]
