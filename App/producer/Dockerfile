# Image personnalisée du Producer Kafka
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY producer.py .

# -u : affichage immédiat des logs
CMD ["python", "-u", "producer.py"]
