# agent_core/Dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV DEMO_MODE=true
ENV POLL_INTERVAL=30
ENV LATENCY_THRESHOLD_MS=500
ENV THREAT_COUNT_THRESHOLD=3

CMD ["python", "-m", "agent_core.orchestrator", "--episodes", "10", "--interval", "5"]
