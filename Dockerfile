FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MEDCONNECT_ENV=production \
    HOST=0.0.0.0 \
    PORT=8000 \
    MEDCONNECT_DATABASE=/data/medconnect.db

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd --gid 10001 medconnect \
    && useradd --uid 10001 --gid medconnect --no-create-home --shell /usr/sbin/nologin medconnect \
    && mkdir /data \
    && chown medconnect:medconnect /data

COPY --chown=medconnect:medconnect app.py 1index.html ./
COPY --chown=medconnect:medconnect templates/ ./templates/

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"

CMD ["python", "app.py"]
