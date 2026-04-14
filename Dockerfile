# --- Stage 1: Build ---
FROM python:3.11-slim as builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    libffi-dev \
    libssl-dev \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels -r requirements.txt

# --- Stage 2: Final ---
FROM python:3.11-slim

WORKDIR /app

# Re-install libmagic1 in the final image
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/wheels /wheels
COPY --from=builder /app/requirements.txt .

RUN pip install --no-cache /wheels/*

COPY . .

# Collect static files (requires dummy secret for build-time execution)
RUN DJANGO_SECRET_KEY=NS-BUILD-KEY python manage.py collectstatic --noinput

# Gunicorn execution on $PORT
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:$PORT --workers 4 --worker-class gevent --timeout 120 intern_web.wsgi:application"]
