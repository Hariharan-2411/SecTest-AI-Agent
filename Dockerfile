# Iris Orchestrator — the headless brain. Multi-arch (builds native on Apple
# Silicon). vendor/brain.mjs is a self-contained bundle built on the host with
# `npm run bundle` BEFORE `docker build`, so this image needs no access to the
# Extension source at runtime.
#
# Base: Node 22 LTS on Debian 13 "trixie", pinned by digest for reproducible
# builds. Trixie carries far fewer CVEs than bookworm did (the old base's criticals
# were all bookworm's perl/tar). Re-pull + bump the digest to take new patches.
FROM node:22-trixie-slim@sha256:8eb619e402eaede1748a3c8173bffab391592812e85136452f781741c7242ddf
WORKDIR /app

# Patch OS packages at build (defense-in-depth; picks up security updates released
# after the base image was cut). Slim base → cheap.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

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

# Run as the unprivileged 'node' user (shipped by the base image). Own /app and the
# data dir so the JSON store is writable; a fresh named volume mounted at /app/data
# inherits this ownership on first init.
RUN mkdir -p /app/data && chown -R node:node /app
USER node

EXPOSE 8790
CMD ["node", "server.js"]
