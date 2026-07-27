# Keyhole sync server.
#
# Node 24 runs the TypeScript sources directly via type stripping, and SQLite
# comes from node:sqlite — so there is no build step and no native module to
# compile. The image is the runtime plus Fastify.

FROM node:24-alpine

ENV NODE_ENV=production
WORKDIR /app

# Install dependencies first so a source edit does not invalidate this layer.
COPY package.json package-lock.json ./
COPY server/package.json ./server/
COPY core/package.json ./core/
COPY app/package.json ./app/
COPY extension/package.json ./extension/
RUN npm ci --omit=dev --workspace @keyhole/server --include-workspace-root

COPY server/src ./server/src

# Vaults live here. Mount a volume or they vanish with the container.
RUN mkdir -p /data && chown -R node:node /data /app
VOLUME ["/data"]

ENV KEYHOLE_DB=/data/keyhole.sqlite \
    KEYHOLE_HOST=0.0.0.0 \
    KEYHOLE_PORT=8787

EXPOSE 8787

# Never run the thing holding everyone's vaults as root.
USER node

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD node -e "fetch('http://127.0.0.1:8787/api/v1/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server/src/index.ts"]
