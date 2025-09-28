FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir requests==2.32.3
COPY run_scheduler.py /app/run_scheduler.py
ENV PYTHONUNBUFFERED=1
CMD ["python","/app/run_scheduler.py"]
