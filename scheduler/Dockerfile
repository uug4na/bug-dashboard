FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY scheduler/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY common /app/common
COPY scheduler/scheduler_job.py /app/scheduler_job.py
ENV PYTHONUNBUFFERED=1
CMD ["python","/app/scheduler_job.py"]
