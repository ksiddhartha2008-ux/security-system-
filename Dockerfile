# syntax=docker/dockerfile:1
FROM node:24-alpine AS web-build
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM node:24-alpine AS api-deps
WORKDIR /app/backend
COPY backend/package*.json ./
RUN npm ci --omit=dev

FROM node:24-alpine
ENV NODE_ENV=production
ENV PORT=4000
ENV SF_DATA_DIR=/data
WORKDIR /app
COPY --from=api-deps /app/backend/node_modules ./backend/node_modules
COPY backend/ ./backend/
COPY --from=web-build /app/frontend/dist ./frontend/dist
RUN mkdir -p /data && addgroup -S secureflow && adduser -S secureflow -G secureflow && chown -R secureflow:secureflow /data /app
USER secureflow
EXPOSE 4000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD node -e "fetch('http://127.0.0.1:4000/api/health/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "backend/src/index.js"]
