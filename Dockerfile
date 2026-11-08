# syntax=docker/dockerfile:1
FROM node:24-alpine AS web-build
WORKDIR /app/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM node:24-alpine AS api-deps
WORKDIR /app/server
COPY server/package*.json ./
RUN npm ci --omit=dev

FROM node:24-alpine
ENV NODE_ENV=production
ENV PORT=4000
ENV SF_DATA_DIR=/data
WORKDIR /app
COPY --from=api-deps /app/server/node_modules ./server/node_modules
COPY server/ ./server/
COPY --from=web-build /app/web/dist ./web/dist
RUN mkdir -p /data && addgroup -S secureflow && adduser -S secureflow -G secureflow && chown -R secureflow:secureflow /data /app
USER secureflow
EXPOSE 4000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD node -e "fetch('http://127.0.0.1:4000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server/src/index.js"]
