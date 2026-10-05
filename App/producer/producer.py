"""
Producer Kafka : simule une sonde réseau (type NetFlow) qui exporte des flux en temps réel.

Lit les fichiers CIC-IDS2017 (dossier GeneratedLabelledFlows / TrafficLabelling) ligne par
ligne et envoie chaque flux réseau dans le topic Kafka "flux-reseau", à une vitesse réglable.
Les valeurs sont envoyées BRUTES (Infinity, NaN, espaces...) : le nettoyage est fait par Spark.
"""

import glob
import json
import os
import sys
import time
from datetime import datetime, timezone

import pandas as pd

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "flux-reseau")
# Liste de fichiers séparés par des virgules, DANS L'ORDRE CHRONOLOGIQUE (les jokers * sont acceptés)
FICHIERS = os.getenv("FICHIERS", "/data/echantillon_reseau_test.csv")
VITESSE = int(os.getenv("VITESSE", "1000"))   # flux envoyés par seconde
LIMITE = int(os.getenv("LIMITE", "0"))        # 0 = tout envoyer

# Champs exportés par la "sonde" (noms CIC-IDS2017, sans les espaces parasites)
COLONNES = [
    "Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port",
    "Protocol", "Timestamp", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Flow Bytes/s",
    "Flow Packets/s", "SYN Flag Count", "RST Flag Count", "Label",
]


def lister_fichiers():
    fichiers = []
    for motif in [m.strip() for m in FICHIERS.split(",") if m.strip()]:
        trouves = sorted(glob.glob(motif))
        if not trouves:
            contenu = os.listdir("/data") if os.path.isdir("/data") else []
            sys.exit(f"Aucun fichier ne correspond à : {motif}\n"
                     f"Contenu du dossier /data : {contenu}\n"
                     "Vérifiez la variable FICHIERS dans docker-compose.yml.")
        fichiers += trouves
    return fichiers


def lire_lignes(chemin):
    """Renvoie les flux du fichier un par un (dictionnaires de textes bruts)."""
    morceaux = pd.read_csv(
        chemin, dtype=str, keep_default_na=False, chunksize=10_000,
        encoding="utf-8", encoding_errors="replace", skipinitialspace=True,
        usecols=lambda c: c.strip() in COLONNES,   # les en-têtes CIC ont des espaces au début
    )
    for morceau in morceaux:
        morceau.columns = [c.strip() for c in morceau.columns]
        manquantes = [c for c in COLONNES if c not in morceau.columns]
        if manquantes:
            sys.exit(f"{chemin} : colonnes manquantes {manquantes}.\n"
                     "Utilisez les fichiers du dossier TrafficLabelling (GeneratedLabelledFlows.zip).")
        for ligne in morceau[COLONNES].itertuples(index=False, name=None):
            yield {col: (None if val is None else str(val)) for col, val in zip(COLONNES, ligne)}


def connecter_kafka(tentatives=30):
    from kafka import KafkaProducer

    for i in range(1, tentatives + 1):
        try:
            return KafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP,
                key_serializer=lambda k: (k or "").encode("utf-8"),
                value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode("utf-8"),
                linger_ms=50,
                acks=1,
            )
        except Exception:   # le nom de l'erreur change selon la version de kafka-python
            print(f"Kafka pas encore prêt ({i}/{tentatives}), nouvel essai dans 5 s...", flush=True)
            time.sleep(5)
    sys.exit("Impossible de se connecter à Kafka.")


def main():
    fichiers = lister_fichiers()
    producer = connecter_kafka()
    print(f"Connecté à Kafka ({KAFKA_BOOTSTRAP}). Sonde réseau démarrée : "
          f"{len(fichiers)} fichier(s) -> topic '{KAFKA_TOPIC}' à {VITESSE} flux/s", flush=True)

    envoyes = 0
    debut = debut_seconde = time.time()
    for chemin in fichiers:
        print(f"Lecture de {os.path.basename(chemin)}", flush=True)
        for flux in lire_lignes(chemin):
            # Heure d'export par la sonde (le flux est « vu passer » maintenant)
            flux["capture_ts"] = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
            # Clé = IP source : tous les flux d'une même machine vont dans la même partition
            producer.send(KAFKA_TOPIC, key=flux.get("Source IP"), value=flux)
            envoyes += 1

            if envoyes % VITESSE == 0:      # limitation de vitesse
                ecoule = time.time() - debut_seconde
                if ecoule < 1:
                    time.sleep(1 - ecoule)
                debut_seconde = time.time()
            if envoyes % 10_000 == 0:
                print(f"  {envoyes:,} flux envoyés".replace(",", " "), flush=True)
            if LIMITE and envoyes >= LIMITE:
                break
        if LIMITE and envoyes >= LIMITE:
            break

    producer.flush()
    producer.close()
    print(f"Terminé : {envoyes:,} flux envoyés en {time.time() - debut:.0f} s."
          .replace(",", " "), flush=True)


if __name__ == "__main__":
    main()
