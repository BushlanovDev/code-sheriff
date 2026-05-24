FROM python:3.14-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /src

COPY pyproject.toml uv.lock ./
RUN uv venv /opt/code-sheriff-venv

COPY app/ app/
RUN UV_PROJECT_ENVIRONMENT=/opt/code-sheriff-venv uv sync --frozen --no-dev


FROM python:3.14-slim

RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid appuser --shell /bin/bash --create-home appuser

COPY --from=builder /opt/code-sheriff-venv /opt/code-sheriff-venv

ENV PATH="/opt/code-sheriff-venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

USER appuser
WORKDIR /repo

ENTRYPOINT ["code-sheriff"]
