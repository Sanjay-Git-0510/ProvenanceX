# Local Hardhat chain and contract tools. Node 22 matches the frontend image.
FROM node:22-slim@sha256:5ec23b7c622b00547753bc6ffd78085dd868a68aeb41c8e0a1418f033e13d96d

ENV HARDHAT_DISABLE_TELEMETRY_PROMPT=true

WORKDIR /app
# I1: strip setuid/setgid bits (su, mount, passwd, ...); nothing here ever needs them.
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + \
    && ! find / -xdev -perm /6000 -type f | grep -q .
RUN chown node:node /app
USER node

COPY --chown=node:node package.json package-lock.json ./
RUN npm ci --ignore-scripts

COPY --chown=node:node . .
# Compile at build time, so the compiler download happens once and the service can run read-only.
RUN npx hardhat compile

EXPOSE 8545
CMD ["npx", "hardhat", "node", "--hostname", "0.0.0.0"]
