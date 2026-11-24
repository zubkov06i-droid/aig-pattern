# Единый Dockerfile для всех микросервисов паттерна AIG.
# Сборка: docker build --build-arg SERVICE=ingest-api -t aig/ingest:1.0 services
FROM python:3.12-slim
ARG SERVICE
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8000
RUN useradd --uid 10001 --create-home aig && mkdir /data && chown 10001 /data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY common/aig_common.py .
COPY ${SERVICE}/app.py .
USER 10001
EXPOSE 8000
CMD uvicorn app:app --host 0.0.0.0 --port ${PORT} --no-access-log
