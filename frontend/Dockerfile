# Digest-pinned (audit finding M6); the same Node 22 base as contracts/Dockerfile.
FROM node:22-slim@sha256:5ec23b7c622b00547753bc6ffd78085dd868a68aeb41c8e0a1418f033e13d96d
WORKDIR /app
# I1: strip setuid/setgid bits (su, mount, passwd, ...); nothing here ever needs them.
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + \
    && ! find / -xdev -perm /6000 -type f | grep -q .

# Run as the unprivileged node user; it must own /app because Vite writes a
# bundled config (vite.config.js.timestamp-*.mjs) and node_modules/.vite at startup.
RUN chown node:node /app
USER node
COPY --chown=node:node package.json package-lock.json ./
RUN npm ci --no-fund --no-audit
COPY --chown=node:node . .
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
