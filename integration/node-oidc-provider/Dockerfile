FROM node:22-alpine

WORKDIR /app
RUN corepack enable

# Install deps first for layer caching. The committed pnpm-lock.yaml pins exact
# versions; --frozen-lockfile fails the build if it drifts from package.json, so
# this PR-gating oracle can't silently change under a new upstream release.
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --prod --frozen-lockfile

COPY server.js ./

EXPOSE 3000
CMD ["node", "server.js"]
