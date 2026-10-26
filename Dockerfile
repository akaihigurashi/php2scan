# PHP2Shell Checker - public website PHP / CMS check
FROM python:3.13-slim

LABEL org.opencontainers.image.title="php2shell-checker" \
      org.opencontainers.image.description="Check whether a website is affected by PHP2Shell (CVE-2026-109618 / CVE-2026-109619)" \
      org.opencontainers.image.licenses="GPL-3.0-only"

# unprivileged user, writable data volume (blocklist cache + audit log)
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin cmsweb \
 && mkdir -p /data && chown 10001:10001 /data

WORKDIR /app
COPY cmsscan.py cmsweb.py ./
COPY static ./static

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CMSWEB_BIND=0.0.0.0 \
    CMSWEB_PORT=8088 \
    STATE_DIRECTORY=/data \
    CMSWEB_AUDIT_DIR=/data/audit \
    CMSWEB_RETENTION_DAYS=30

USER 10001
VOLUME ["/data"]
EXPOSE 8088

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8088/healthz', timeout=3)" || exit 1

ENTRYPOINT ["python3", "cmsweb.py"]
