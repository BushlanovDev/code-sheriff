FROM python:3.13-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /src

COPY pyproject.toml uv.lock ./
RUN uv venv /opt/review-agent-venv && \
    uv pip install --python /opt/review-agent-venv/bin/python -r pyproject.toml

COPY app/ app/
RUN uv pip install --python /opt/review-agent-venv/bin/python .


FROM python:3.13-slim

RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid appuser --shell /bin/bash --create-home appuser

COPY --from=builder /opt/review-agent-venv /opt/review-agent-venv

ENV PATH="/opt/review-agent-venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

USER appuser
WORKDIR /repo

ENTRYPOINT ["review-agent"]
