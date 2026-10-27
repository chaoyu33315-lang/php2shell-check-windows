FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70
WORKDIR /app
COPY wordpress_check.py LICENSE LICENSING.md /app/
COPY integrations/__init__.py /app/integrations/__init__.py
COPY integrations/worker /app/integrations/worker
ARG CHECKER_REVISION
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 CT_SCAN_REVISION=${CHECKER_REVISION}
RUN test -n "$CHECKER_REVISION" && mkdir -p /var/lib/ct-scan /run/ct-scan && chmod 700 /var/lib/ct-scan /run/ct-scan
# The controller reads the root-only API key; scanner children drop to 65534.
USER 0:0
ENTRYPOINT ["python", "-m", "integrations.worker.service"]
