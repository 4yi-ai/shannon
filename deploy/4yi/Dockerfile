# Shannon v3.5.0 standalone build. No host runtime access or privileged startup.
ARG NODE_BASE=public.ecr.aws/docker/library/node:22-bookworm-slim@sha256:5ec23b7c622b00547753bc6ffd78085dd868a68aeb41c8e0a1418f033e13d96d
FROM ${NODE_BASE} AS builder
WORKDIR /app
RUN npm install -g --ignore-scripts pnpm@10.33.0
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml .npmrc ./
COPY apps/worker/package.json ./apps/worker/
COPY apps/cli/package.json ./apps/cli/
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm --filter @shannon/worker run build
RUN mkdir -p /source && tar --exclude='./node_modules' --exclude='*/node_modules' --exclude='./.pnpm-store' --exclude='./.git' --exclude='*/dist' --exclude='./standalone-data' --exclude='./.env' -czf /source/shannon.tar.gz .
RUN rm -rf node_modules apps/*/node_modules && pnpm install --frozen-lockfile --prod

FROM ${NODE_BASE} AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 git curl bash ca-certificates chromium xz-utils fonts-noto-cjk \
    && rm -rf /var/lib/apt/lists/*
ARG TYPST_VERSION=0.14.2
RUN case "$(uname -m)" in \
      x86_64) TYPST_ARCH=x86_64-unknown-linux-musl ;; \
      aarch64) TYPST_ARCH=aarch64-unknown-linux-musl ;; \
      *) exit 1 ;; esac \
    && mkdir -p /tmp/typst-dl && cd /tmp/typst-dl \
    && curl --retry 3 -fsSL "https://github.com/typst/typst/releases/download/v${TYPST_VERSION}/typst-${TYPST_ARCH}.tar.xz" -o typst.tar.xz \
    && tar -xJf typst.tar.xz \
    && mv "typst-${TYPST_ARCH}/typst" /usr/local/bin/typst \
    && cd / && rm -rf /tmp/typst-dl && typst --version
WORKDIR /app
RUN npm install -g --ignore-scripts @playwright/cli@0.1.1 \
    && mkdir -p /tmp/.claude/skills \
    && cp -r /usr/local/lib/node_modules/@playwright/cli/node_modules/playwright/lib/skill /tmp/.claude/skills/playwright-cli
COPY --from=builder /app/package.json /app/pnpm-workspace.yaml /app/pnpm-lock.yaml /app/.npmrc /app/
COPY --from=builder /app/4yi-app.json /app/4yi-app.json
COPY --from=builder /app/node_modules /app/node_modules
COPY --from=builder /app/apps/worker /app/apps/worker
COPY --from=builder /app/apps/cli/package.json /app/apps/cli/package.json
COPY --from=builder /app/apps/standalone /app/apps/standalone
COPY --from=builder /app/deploy/4yi /app/deploy/4yi
COPY --from=builder /source/shannon.tar.gz /usr/share/shannon/source.tar.gz
COPY LICENSE THIRD_PARTY_NOTICES.md /usr/share/licenses/shannon/
COPY LICENSES/ /usr/share/licenses/shannon/LICENSES/
RUN groupadd -g 1001 pentest && useradd -u 1001 -g 1001 -s /bin/bash -M pentest \
    && git config --system user.email 'agent@localhost' \
    && git config --system user.name 'Pentest Agent' \
    && mkdir -p /app/data /tmp/.cache /tmp/.config /tmp/.npm /tmp/.pi/agent \
    && chown -R 1001:1001 /app/data /tmp/.claude /tmp/.cache /tmp/.config /tmp/.npm /tmp/.pi
RUN ln -s /app/apps/worker/dist/scripts/save-deliverable.js /usr/local/bin/save-deliverable \
    && ln -s /app/apps/worker/dist/scripts/generate-totp.js /usr/local/bin/generate-totp \
    && ln -s /app/apps/worker/dist/scripts/set-report-meta.js /usr/local/bin/set-report-meta \
    && chmod +x /app/apps/worker/dist/scripts/save-deliverable.js /app/apps/worker/dist/scripts/generate-totp.js /app/apps/worker/dist/scripts/set-report-meta.js
ENV NODE_ENV=production SHANNON_DOCKER=true PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    PLAYWRIGHT_MCP_EXECUTABLE_PATH=/usr/bin/chromium PLAYWRIGHT_MCP_SANDBOX=false npm_config_cache=/tmp/.npm \
    HOME=/tmp XDG_CACHE_HOME=/tmp/.cache XDG_CONFIG_HOME=/tmp/.config DATA_DIR=/app/data
USER 1001:1001
EXPOSE 8080
ENTRYPOINT ["python3", "-m", "apps.standalone.server"]
