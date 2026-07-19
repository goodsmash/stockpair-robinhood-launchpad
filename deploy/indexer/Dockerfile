FROM node:22.16.0-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV HOST=0.0.0.0
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force
COPY artifacts/solc ./artifacts/solc
COPY config ./config
COPY services/indexer ./services/indexer
USER node
EXPOSE 8787
CMD ["node", "services/indexer/src/server.mjs"]
