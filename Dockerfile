FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PROVENANCE_HOME=/data PROVENANCE_BIND=0.0.0.0
RUN useradd --system --uid 10001 --home /app provenance && mkdir /data && chown provenance /data
WORKDIR /app
COPY provenance ./provenance
COPY deploy/entrypoint.sh /entrypoint.sh
USER provenance
VOLUME /data
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8787/healthz',timeout=2)"
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
