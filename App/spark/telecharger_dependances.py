"""Télécharge le connecteur Kafka de Spark pendant la construction de l'image (docker build),
pour qu'il soit déjà présent au démarrage du pipeline."""

from config import PAQUET_KAFKA, creer_session

print(f"Téléchargement de {PAQUET_KAFKA} ...")
creer_session("telechargement", avec_kafka=True).stop()
print("Connecteur Kafka prêt.")
