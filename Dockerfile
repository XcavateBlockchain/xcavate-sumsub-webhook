FROM node:22-slim AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ ./src/

RUN npm run build

# ── Production image ────────────────────────────────────────────────────
FROM node:22-slim

WORKDIR /app

# Install dependencies only (no devDeps needed at runtime)
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Copy built app
COPY --from=builder /app/dist ./dist

ENV NODE_ENV=production
ENV PORT=8005

EXPOSE 8005

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:8005/health || exit 1

CMD ["node", "dist/index.js"]