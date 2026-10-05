"""Configuration commune aux jobs Spark (lue depuis les variables d'environnement)."""

import os

import pyspark
from pyspark.sql import SparkSession

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "flux-reseau")
MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongodb:27017")
MONGO_DB = os.getenv("MONGO_DB", "ids_reseau")
DOSSIER_SORTIE = os.getenv("DOSSIER_SORTIE", "/data/output")
DOSSIER_CHECKPOINT = os.getenv("DOSSIER_CHECKPOINT", "/data/checkpoints")

# Connecteur Kafka pour Spark : même version que PySpark (Scala 2.13 pour Spark 4, 2.12 pour Spark 3)
_VERSION_SPARK = pyspark.__version__.split("+")[0]
_SCALA = "2.13" if int(_VERSION_SPARK.split(".")[0]) >= 4 else "2.12"
PAQUET_KAFKA = f"org.apache.spark:spark-sql-kafka-0-10_{_SCALA}:{_VERSION_SPARK}"


def creer_session(nom, avec_kafka=True):
    builder = (
        SparkSession.builder
        .appName(nom)
        .master(os.getenv("SPARK_MASTER", "local[*]"))
        .config("spark.driver.memory", os.getenv("SPARK_DRIVER_MEMORY", "2g"))
        .config("spark.sql.session.timeZone", "UTC")
        .config("spark.sql.shuffle.partitions", "8")
    )
    if avec_kafka:
        builder = builder.config("spark.jars.packages", PAQUET_KAFKA)
    spark = builder.getOrCreate()
    spark.sparkContext.setLogLevel("WARN")

    # Les workers Python de Spark doivent pouvoir importer nos modules
    dossier = os.path.dirname(os.path.abspath(__file__))
    for module in ("config.py", "nettoyage.py", "detection.py", "mongo_utils.py"):
        if not os.path.exists(os.path.join(dossier, module)):
            continue
        spark.sparkContext.addPyFile(os.path.join(dossier, module))
    return spark
