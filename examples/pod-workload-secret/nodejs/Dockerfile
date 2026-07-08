# Pin a digest in your own build so the running image matches the digest you approve in
# the portal (Layer 4): node:22-slim@sha256:...
FROM node:22-slim
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

COPY astis-workload.js main.js ./

# Run as non-root; the decrypted credentials live only in this process's memory.
USER node
ENTRYPOINT ["node", "main.js"]
