# syntax=docker/dockerfile:1.7
ARG NODE_IMAGE=node:22.22.2-bookworm-slim

FROM ${NODE_IMAGE} AS build
WORKDIR /app
ENV CI=1
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
COPY migrations ./migrations
COPY openapi.yaml README.md LICENSE NOTICE ./
# A packed application needs a publishable lock; package-lock.json is excluded by npm pack.
RUN npm run build \
 && cp package-lock.json npm-shrinkwrap.json \
 && npm pack --pack-destination /tmp

FROM ${NODE_IMAGE} AS runtime
ARG IMAGE_REVISION=unknown
ARG IMAGE_VERSION=0.1.0-dev
WORKDIR /app
ENV NODE_ENV=production PORT=3000 HOST=0.0.0.0 SELFHOST_IMAGE_VERSION=${IMAGE_VERSION}
LABEL org.opencontainers.image.source="https://github.com/AgentWorkforce/relay-control" \
      org.opencontainers.image.revision="${IMAGE_REVISION}" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /tmp/relay-control-*.tgz /tmp/package.tgz
RUN npm init -y >/dev/null \
 && npm install --omit=dev --ignore-scripts --no-audit --no-fund /tmp/package.tgz \
 && rm /tmp/package.tgz \
 && chown -R node:node /app
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "node_modules/relay-control/dist/server.js"]
