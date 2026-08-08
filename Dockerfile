FROM python:3.11-slim

LABEL maintainer="Ankit <https://github.com/Ankitavasudev>"
LABEL description="K8s Health Monitor - Kubernetes Cluster Health Checker"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY k8s_monitor.py .

RUN chmod +x k8s_monitor.py

ENTRYPOINT ["python", "k8s_monitor.py"]
CMD ["check"]
