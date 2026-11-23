# Night Desk image: the `nightdesk` package (okf/architecture/deployment.md#the-package) on its locked dependencies,
# run as an unprivileged user. Built on your machine by the installer (deploy/install.sh) or `docker compose build`.

# --- 1. build the wheel (it carries the web client and the docs bundle inside the package)
FROM python:3.14-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.12.19 /uv /usr/local/bin/
WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./
COPY osinthub ./osinthub
COPY web ./web
COPY okf ./okf
RUN uv build --wheel --out-dir /dist

# --- 2. the app
FROM python:3.14-slim
COPY --from=ghcr.io/astral-sh/uv:0.12.19 /uv /uvx /usr/local/bin/
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never

# Dependencies first (exactly the locked versions), so a code change does not invalidate this layer. The repo-only
# dependency groups (the Mac AI libraries) are left out.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-default-groups --no-install-project
COPY --from=build /dist/ /tmp/dist/
RUN uv pip install --python /app/.venv --no-deps /tmp/dist/*.whl && rm -rf /tmp/dist

# An unprivileged user owns the data folder. Compose runs the container as the installing user's id (ND_UID/ND_GID)
# so files in a host data folder belong to that user; 1000 is the default for a plain `docker run`.
RUN useradd --uid 1000 --user-group --no-create-home --home-dir /tmp nightdesk && mkdir -p /data && chown nightdesk:nightdesk /data
USER nightdesk

# 0.0.0.0 inside the container so Caddy (or a port mapping) can reach it. A non-loopback bind refuses to start
# without OSINTHUB_PASSWORD; docker compose sets OSINTHUB_TRUST_PROXY_AUTH=1 instead, because Caddy is the only way
# in there. Never publish 8787 to the network. For a quick local test give it a password and publish on loopback
# only:  docker run -e OSINTHUB_PASSWORD -p 127.0.0.1:8787:8787 -v osint-lake:/data <image>
ENV OSINTHUB_HOST=0.0.0.0 \
    OSINTHUB_PORT=8787 \
    OSINTHUB_LAKE=/data \
    HOME=/tmp \
    PATH="/app/.venv/bin:$PATH"

VOLUME /data
EXPOSE 8787 8788

HEALTHCHECK --interval=15s --timeout=5s --start-period=300s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8787/api/health', timeout=4).status == 200 else 1)"

CMD ["nightdesk"]
