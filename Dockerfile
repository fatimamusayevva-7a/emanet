# syntax=docker/dockerfile:1
# Çoxmərhələli build: son obrazda pip/kompilyator yoxdur, root olmayan istifadəçi, yalnız-oxu fayl sistemi.
FROM python:3.12-slim AS build
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim
LABEL org.opencontainers.image.title="Emanet" \
      org.opencontainers.image.description="Rəqəmsal etibar seyfi — Shamir + zero-knowledge + dead man's switch" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 EMANET_DATA_DIR=/data
RUN groupadd -r -g 10001 emanet && useradd -r -u 10001 -g emanet -d /app -s /usr/sbin/nologin emanet \
    && mkdir -p /data && chown emanet:emanet /data
COPY --from=build /install /usr/local
WORKDIR /app
COPY --chown=root:root emanet ./emanet
COPY --chown=root:root web ./web
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/health')" || exit 1
# Tək worker: SQLite yazıları üçün; paralellik thread-lərlə
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "8", "--timeout", "60", \
     "--access-logfile", "-", "--forwarded-allow-ips", "*", "emanet.wsgi:app"]
