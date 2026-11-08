FROM node:22-slim
WORKDIR /app
# Run as the unprivileged node user; it must own /app because Vite writes a
# bundled config (vite.config.js.timestamp-*.mjs) and node_modules/.vite at startup.
RUN chown node:node /app
USER node
COPY --chown=node:node package.json package-lock.json ./
RUN npm ci --no-fund --no-audit
COPY --chown=node:node . .
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
