# Image personnalisée Spark : PySpark + pymongo + connecteur Spark-Kafka déjà téléchargé
FROM quay.io/jupyter/pyspark-notebook:latest

# Le contrôle de santé de l'image concerne Jupyter, qu'on n'utilise pas
HEALTHCHECK NONE

# Client MongoDB pour Python
RUN pip install --no-cache-dir "pymongo>=4.6"

WORKDIR /app

# 1) Pré-téléchargement du connecteur Spark-Kafka (start.sh active PySpark dans cette image).
#    Étape séparée : elle reste en cache même quand le code change.
COPY --chown=1000:100 config.py telecharger_dependances.py /app/
RUN start.sh python /app/telecharger_dependances.py

# 2) Le code (également partagé en volume dans docker-compose.yml)
COPY --chown=1000:100 . /app

CMD ["python", "-u", "/app/streaming_job.py"]
