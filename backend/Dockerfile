FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# git is required for hardened shallow clones of GitHub sources (app/scanners/git_fetch.py).
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system app && useradd --system --gid app --home /app app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
RUN mkdir -p /app/workspace && chown -R app:app /app
USER app

EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
