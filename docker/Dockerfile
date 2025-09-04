FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./

# 安装 git 和构建依赖
RUN apk add --no-cache git python3 make g++

RUN npm install

FROM node:20-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM node:20-alpine
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY package.json ./
RUN npm install --omit=dev
CMD ["node", "dist/index.js"]
