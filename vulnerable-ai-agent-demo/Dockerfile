# INTENTIONALLY VULNERABLE DEMO IMAGE - security testing / detection-validation only.
# Do not push to a public registry or expose on a real network.
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 8080

ENV JWT_SECRET=supersecret-demo-key

CMD ["python", "app.py"]
