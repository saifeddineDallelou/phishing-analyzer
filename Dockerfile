# Phishing Analyzer container.
#   docker build -t phishing-analyzer .
#   docker run --rm -p 127.0.0.1:8000:8000 --env-file .env phishing-analyzer
# API keys are passed at run time (--env-file), never copied into the image.

FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first: this layer is cached and only rebuilt when requirements.txt changes.
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app/ app/
COPY models/ models/

# The parser reads attacker-made files: if it is ever exploited, the attacker gets
# an unprivileged account, not root.
RUN useradd --create-home --uid 10001 analyzer
USER analyzer

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import sys, urllib.request; sys.exit(urllib.request.urlopen('http://127.0.0.1:8000/health').status != 200)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
