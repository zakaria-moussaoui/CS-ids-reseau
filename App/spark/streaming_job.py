"""
Job Spark Structured Streaming : Kafka -> nettoyage + détection -> MongoDB + Parquet

Deux requêtes tournent en parallèle sur le même topic Kafka :
  1. STOCKAGE   : toutes les 10 s, nettoie les nouveaux flux, les écrit dans MongoDB
                  (collection "flux") et en Parquet, et journalise le nettoyage.
  2. DÉTECTION  : agrège les flux par fenêtre de temps et lève des alertes
                  (collection "alertes") : scan de ports, flood/DDoS, brute force.
"""

import os
from datetime import datetime, timezone

from pyspark.sql import functions as F

from config import (DOSSIER_CHECKPOINT, DOSSIER_SORTIE, KAFKA_BOOTSTRAP, KAFKA_TOPIC,
                    creer_session)
from detection import agreger_fenetres, traiter_fenetres
from mongo_utils import creer_index, ecrire_alertes, ecrire_mongo, journaliser
from nettoyage import SCHEMA_BRUT, nettoyer


def traiter_batch(df_brut, batch_id, ecrire=ecrire_mongo, journal=journaliser,
                  dossier_sortie=DOSSIER_SORTIE):
    """Requête 1 : nettoyage et stockage d'un micro-batch."""
    df_brut = df_brut.persist()
    recus = df_brut.count()
    if recus == 0:
        df_brut.unpersist()
        return

    prepares, valides, propres = nettoyer(df_brut)
    prepares, propres = prepares.persist(), propres.persist()

    stats = prepares.agg(
        F.sum(F.col("debit_invalide").cast("int")).alias("debits_infinis"),
        F.sum(F.col("horodatage_corrige").cast("int")).alias("horodatages_corriges"),
    ).first()
    nb_valides = valides.count()
    nb_propres = propres.count()
    par_label = {r["label"]: r["count"] for r in propres.groupBy("label").count().collect()}

    ecrire(propres, "flux", mode="upsert")
    propres.write.mode("append").partitionBy("jour").parquet(f"{dossier_sortie}/flux")

    nb_attaques = sum(v for k, v in par_label.items() if k != "NORMAL")
    journal({
        "batch_id": int(batch_id),
        "traite_le": datetime.now(timezone.utc),
        "flux_recus": recus,
        "flux_valides": nb_propres,
        "flux_rejetes": recus - nb_valides,
        "doublons_supprimes": nb_valides - nb_propres,
        "debits_infinis_recalcules": int(stats["debits_infinis"] or 0),
        "horodatages_corriges": int(stats["horodatages_corriges"] or 0),
        "flux_attaques": nb_attaques,
        "par_label": par_label,
        "taux_rejet_pct": round(100 * (recus - nb_valides) / recus, 2),
    })
    print(f"[batch {batch_id}] reçus={recus}  valides={nb_propres}  "
          f"rejetés={recus - nb_valides}  doublons={nb_valides - nb_propres}  "
          f"attaques={nb_attaques}", flush=True)

    for df in (df_brut, prepares, propres):
        df.unpersist()


def demarrer(spark, flux_bruts, dossier_checkpoint=DOSSIER_CHECKPOINT,
             traiter=traiter_batch, ecrire_alertes_fn=ecrire_alertes, trigger="10 seconds"):
    """Lance les 2 requêtes de streaming (source au choix : Kafka, ou fichiers pour les tests)."""
    stockage = (
        flux_bruts.writeStream
        .foreachBatch(traiter)
        .option("checkpointLocation", f"{dossier_checkpoint}/stockage")
        .trigger(processingTime=trigger)
        .queryName("stockage")
        .start()
    )
    detection = (
        agreger_fenetres(flux_bruts).writeStream
        .outputMode("update")   # seules les fenêtres modifiées sont transmises
        .foreachBatch(lambda df, bid: traiter_fenetres(df, bid, ecrire_alertes_fn))
        .option("checkpointLocation", f"{dossier_checkpoint}/detection")
        .trigger(processingTime=trigger)
        .queryName("detection")
        .start()
    )
    return stockage, detection


def lire_kafka(spark):
    brut = (
        spark.readStream.format("kafka")
        .option("kafka.bootstrap.servers", KAFKA_BOOTSTRAP)
        .option("subscribe", KAFKA_TOPIC)
        .option("startingOffsets", "earliest")
        .option("maxOffsetsPerTrigger", int(os.getenv("MAX_FLUX_PAR_BATCH", "20000")))
        .option("failOnDataLoss", "false")
        .load()
    )
    return (brut.select(F.from_json(F.col("value").cast("string"), SCHEMA_BRUT).alias("v"))
                .select("v.*"))


def main():
    spark = creer_session("ids-reseau-streaming", avec_kafka=True)
    creer_index()
    demarrer(spark, lire_kafka(spark))
    print(f"IDS démarré : topic '{KAFKA_TOPIC}' -> MongoDB (flux, alertes) + Parquet. "
          "Interface Spark : http://localhost:4040", flush=True)
    spark.streams.awaitAnyTermination()


if __name__ == "__main__":
    main()
