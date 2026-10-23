# Iris Orchestrator — the headless brain. Multi-arch (builds native on Apple
# Silicon). vendor/brain.mjs is a self-contained bundle built on the host with
# `npm run bundle` BEFORE `docker build`, so this image needs no access to the
# Extension source at runtime.
FROM node:20-bookworm-slim
WORKDIR /app

# No runtime deps today (Node built-ins + global fetch + bundled brain). Copy
# manifest first for layer caching; install prod deps only if any exist.
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund || true

COPY lib ./lib
COPY web ./web
COPY scripts ./scripts
COPY server.js ./server.js
COPY vendor/brain.mjs ./vendor/brain.mjs

RUN test -f vendor/brain.mjs || (echo "ERROR: run 'npm run bundle' on the host before docker build" && exit 1)

EXPOSE 8790
CMD ["node", "server.js"]
