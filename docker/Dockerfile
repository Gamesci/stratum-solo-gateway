FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install

FROM node:20-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules node_modules
COPY tsconfig.json package.json ./
COPY src ./src
RUN npx tsc

FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/dist dist
COPY package.json ./
RUN npm install --omit=dev
CMD ["node", "dist/index.js"]
