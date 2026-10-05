"""
Job Spark batch : analyse du trafic réseau nettoyé + évaluation du détecteur temps réel.

Utilise les 3 API de Spark vues en cours (DataFrame, RDD, SparkSQL).
Résultats : MongoDB (collections stats_*) et CSV dans /data/output/rapports.

Lancement : docker compose run --rm spark-analytics
"""

import os
import sys

from pyspark.sql import functions as F, types as T

from config import DOSSIER_SORTIE, creer_session
from mongo_utils import ecrire_mongo, lire_alertes


# ---------------------------------------------------------------------------
# 1. API DataFrame
# ---------------------------------------------------------------------------
def calculer_stats(flux):
    total = flux.count()
    attaques = flux.filter("est_attaque")
    stats = {}

    # Répartition du trafic : normal vs chaque type d'attaque
    stats["stats_trafic_par_label"] = (
        flux.groupBy("label")
        .agg(F.count("*").alias("nb_flux"),
             F.sum("total_octets").alias("total_octets"),
             F.round(F.avg("duree_ms"), 2).alias("duree_moyenne_ms"))
        .withColumn("pourcentage", F.round(100 * F.col("nb_flux") / F.lit(total), 2))
        .orderBy(F.desc("nb_flux"))
    )

    # Protocoles (TCP / UDP...) : trafic normal vs attaques
    stats["stats_protocoles"] = (
        flux.groupBy("protocole_nom")
        .agg(F.count("*").alias("nb_flux"),
             F.sum(F.col("est_attaque").cast("int")).alias("nb_flux_attaque"))
        .withColumn("part_attaque_pct", F.round(100 * F.col("nb_flux_attaque") / F.col("nb_flux"), 2))
        .orderBy(F.desc("nb_flux"))
    )

    # Ports et services les plus visés par les attaques
    stats["stats_ports_attaques"] = (
        attaques.groupBy("port_dst", "service")
        .agg(F.count("*").alias("nb_flux_attaque"),
             F.count_distinct("ip_src").alias("nb_attaquants"),
             F.concat_ws(", ", F.array_sort(F.collect_set("label"))).alias("types_attaque"))
        .orderBy(F.desc("nb_flux_attaque"))
        .limit(20)
    )

    # Machines à l'origine des attaques
    stats["stats_sources_attaque"] = (
        attaques.groupBy("ip_src", "ip_src_type")
        .agg(F.count("*").alias("nb_flux_attaque"),
             F.count_distinct("ip_dst").alias("nb_cibles"),
             F.count_distinct("port_dst").alias("nb_ports_touches"),
             F.concat_ws(", ", F.array_sort(F.collect_set("label"))).alias("types_attaque"))
        .orderBy(F.desc("nb_flux_attaque"))
        .limit(20)
    )

    # Chronologie minute par minute (on voit les attaques apparaître)
    stats["stats_trafic_par_minute"] = (
        flux.groupBy(F.date_trunc("minute", "date_flux").alias("minute"))
        .agg(F.sum((~F.col("est_attaque")).cast("int")).alias("flux_normaux"),
             F.sum(F.col("est_attaque").cast("int")).alias("flux_attaques"))
        .orderBy("minute")
    )

    # Sens du trafic (interne, entrant, sortant)
    stats["stats_sens_trafic"] = (
        flux.groupBy("sens")
        .agg(F.count("*").alias("nb_flux"),
             F.sum(F.col("est_attaque").cast("int")).alias("nb_flux_attaque"))
        .orderBy(F.desc("nb_flux"))
    )
    return stats


# ---------------------------------------------------------------------------
# 2. API RDD (cours : map, filter, reduceByKey, groupByKey, sortBy, distinct)
# ---------------------------------------------------------------------------
def calculer_stats_rdd(spark, flux):
    rdd = flux.select("ip_src", "ip_dst", "port_dst", "service", "total_octets").rdd

    # Conversations les plus volumineuses : map -> ((src, dst), octets), reduceByKey, sortBy
    conversations = (
        rdd.map(lambda f: ((f.ip_src, f.ip_dst), f.total_octets))
        .reduceByKey(lambda a, b: a + b)
        .sortBy(lambda p: p[1], ascending=False)
        .map(lambda p: (p[0][0], p[0][1], int(p[1])))
    )

    # Nombre de ports différents contactés par chaque source : distinct + groupByKey
    ports_par_source = (
        rdd.map(lambda f: (f.ip_src, f.port_dst))
        .distinct()
        .groupByKey()
        .mapValues(len)
        .sortBy(lambda p: p[1], ascending=False)
    )

    # Services les plus utilisés : map -> (service, 1), reduceByKey
    services = (
        rdd.filter(lambda f: f.service is not None)
        .map(lambda f: (f.service, 1))
        .reduceByKey(lambda a, b: a + b)
        .sortBy(lambda p: p[1], ascending=False)
    )

    sc = spark.sparkContext
    return {
        "stats_rdd_conversations": spark.createDataFrame(
            sc.parallelize(conversations.take(20)), "ip_src string, ip_dst string, total_octets long"),
        "stats_rdd_ports_par_source": spark.createDataFrame(
            sc.parallelize(ports_par_source.take(20)), "ip_src string, nb_ports_distincts long"),
        "stats_rdd_services": spark.createDataFrame(services, "service string, nb_flux long"),
    }


# ---------------------------------------------------------------------------
# 3. SparkSQL + évaluation du détecteur
# ---------------------------------------------------------------------------
REQUETES_SQL = {
    # « Empreinte » de chaque type de trafic : une attaque ne ressemble pas à du trafic normal
    "stats_sql_profil_trafic": """
        SELECT label,
               COUNT(*)                         AS nb_flux,
               ROUND(AVG(duree_ms), 2)          AS duree_moyenne_ms,
               ROUND(AVG(total_paquets), 2)     AS paquets_moyens,
               ROUND(AVG(total_octets), 2)      AS octets_moyens,
               ROUND(AVG(flags_syn), 3)         AS syn_moyen,
               ROUND(AVG(paquets_retour), 2)    AS paquets_retour_moyens
        FROM flux
        GROUP BY label
        ORDER BY nb_flux DESC
    """,
    # Ce que chaque attaquant a scanné
    "stats_sql_scans": """
        SELECT ip_src, ip_dst,
               COUNT(DISTINCT port_dst) AS ports_scannes,
               MIN(port_dst)            AS port_min,
               MAX(port_dst)            AS port_max,
               MIN(date_flux)           AS debut,
               MAX(date_flux)           AS fin
        FROM flux
        WHERE label = 'PORTSCAN'
        GROUP BY ip_src, ip_dst
        ORDER BY ports_scannes DESC
    """,
}

# Chaque alerte est-elle confirmée par la vérité terrain (les labels du dataset) ?
SQL_ALERTES_VERIFIEES = """
    SELECT a.type, a.gravite, a.ip_src, a.ip_dst, a.debut_fenetre, a.valeur,
           COUNT(f.ip_src)                                   AS flux_dans_fenetre,
           SUM(CASE WHEN f.est_attaque THEN 1 ELSE 0 END)    AS flux_attaque,
           ROUND(100 * SUM(CASE WHEN f.est_attaque THEN 1 ELSE 0 END) / COUNT(f.ip_src), 2)
                                                             AS part_attaque_pct,
           CONCAT_WS(', ', ARRAY_SORT(COLLECT_SET(CASE WHEN f.est_attaque THEN f.label END)))
                                                             AS labels_reels
    FROM {alertes} a
    LEFT JOIN flux f
      ON f.ip_src = a.ip_src AND f.ip_dst = a.ip_dst
     AND f.date_flux >= a.debut_fenetre AND f.date_flux < a.fin_fenetre
    GROUP BY a.type, a.gravite, a.ip_src, a.ip_dst, a.debut_fenetre, a.valeur
"""

SQL_EVALUATION = """
    SELECT type,
           COUNT(*)                                             AS nb_alertes,
           SUM(CASE WHEN part_attaque_pct >= 50 THEN 1 ELSE 0 END) AS vraies_alertes,
           SUM(CASE WHEN part_attaque_pct <  50 THEN 1 ELSE 0 END) AS fausses_alertes,
           ROUND(100 * SUM(CASE WHEN part_attaque_pct >= 50 THEN 1 ELSE 0 END) / COUNT(*), 2)
                                                                AS precision_pct
    FROM {verifiees}
    GROUP BY type
    ORDER BY nb_alertes DESC
"""

# Quelle part de chaque type d'attaque a été couverte par au moins une alerte ?
SQL_COUVERTURE = """
    SELECT f.label,
           COUNT(*)                                                    AS nb_flux_attaque,
           SUM(CASE WHEN a.ip_src IS NOT NULL THEN 1 ELSE 0 END)       AS flux_detectes,
           ROUND(100 * SUM(CASE WHEN a.ip_src IS NOT NULL THEN 1 ELSE 0 END) / COUNT(*), 2)
                                                                       AS taux_detection_pct
    FROM flux f
    LEFT JOIN (SELECT DISTINCT ip_src, ip_dst, debut_fenetre, fin_fenetre FROM {alertes}) a
      ON f.ip_src = a.ip_src AND f.ip_dst = a.ip_dst
     AND f.date_flux >= a.debut_fenetre AND f.date_flux < a.fin_fenetre
    WHERE f.est_attaque
    GROUP BY f.label
    ORDER BY nb_flux_attaque DESC
"""

SCHEMA_ALERTES = T.StructType([
    T.StructField("type", T.StringType()), T.StructField("gravite", T.StringType()),
    T.StructField("ip_src", T.StringType()), T.StructField("ip_dst", T.StringType()),
    T.StructField("debut_fenetre", T.TimestampType()), T.StructField("fin_fenetre", T.TimestampType()),
    T.StructField("valeur", T.LongType()),
])


def calculer_stats_sql(spark, flux, alertes_docs):
    flux.createOrReplaceTempView("flux")
    resultats = {nom: spark.sql(sql) for nom, sql in REQUETES_SQL.items()}

    if alertes_docs:
        lignes = [(a["type"], a["gravite"], a["ip_src"], a["ip_dst"], a["debut_fenetre"],
                   a["fin_fenetre"], int(a["valeur"])) for a in alertes_docs]
        noms = {"alertes": "alertes", "verifiees": "alertes_verifiees"}
        spark.createDataFrame(lignes, SCHEMA_ALERTES).createOrReplaceTempView("alertes")
        verifiees = spark.sql(SQL_ALERTES_VERIFIEES.format(**noms)).cache()
        verifiees.createOrReplaceTempView("alertes_verifiees")
        resultats["stats_sql_alertes_verifiees"] = verifiees.orderBy("debut_fenetre")
        resultats["stats_sql_evaluation_detection"] = spark.sql(SQL_EVALUATION.format(**noms))
        resultats["stats_sql_couverture_attaques"] = spark.sql(SQL_COUVERTURE.format(**noms))
    else:
        print("Aucune alerte dans MongoDB : évaluation du détecteur ignorée.")
    return resultats


# ---------------------------------------------------------------------------
# 4. Comparaison des règles v1 / v2 (tuning du détecteur)
#    Les MÊMES fonctions que le streaming sont rejouées en batch sur le Parquet.
# ---------------------------------------------------------------------------
def comparer_versions(spark, flux):
    from detection import agreger_fenetres_propres, construire_alertes, filtre_candidates

    flux.createOrReplaceTempView("flux")
    fenetres = agreger_fenetres_propres(flux).filter(filtre_candidates()).collect()
    noms = {"alertes": "alertes_cmp", "verifiees": "alertes_cmp_verifiees"}
    precision, detection = [], []
    for version in ("v1", "v2"):
        docs = construire_alertes(fenetres, version)
        if not docs:
            continue
        lignes = [(a["type"], a["gravite"], a["ip_src"], a["ip_dst"], a["debut_fenetre"],
                   a["fin_fenetre"], int(a["valeur"])) for a in docs]
        spark.createDataFrame(lignes, SCHEMA_ALERTES).createOrReplaceTempView("alertes_cmp")
        spark.sql(SQL_ALERTES_VERIFIEES.format(**noms)).createOrReplaceTempView("alertes_cmp_verifiees")
        par_type = spark.sql(SQL_EVALUATION.format(**noms)).collect()
        for r in par_type:
            precision.append((version, r["type"], r["nb_alertes"], r["vraies_alertes"],
                              r["fausses_alertes"], float(r["precision_pct"])))
        total = sum(r["nb_alertes"] for r in par_type)
        vraies = sum(r["vraies_alertes"] for r in par_type)
        precision.append((version, "TOTAL", total, vraies, total - vraies,
                          round(100 * vraies / total, 2) if total else 0.0))
        for r in spark.sql(SQL_COUVERTURE.format(**noms)).collect():
            detection.append((version, r["label"], r["nb_flux_attaque"], r["flux_detectes"],
                              float(r["taux_detection_pct"])))

    return {
        "stats_comparaison_precision": spark.createDataFrame(
            precision, "version string, type string, nb_alertes long, vraies_alertes long, "
                       "fausses_alertes long, precision_pct double").orderBy("type", "version"),
        "stats_comparaison_detection": spark.createDataFrame(
            detection, "version string, label string, nb_flux_attaque long, flux_detectes long, "
                       "taux_detection_pct double").orderBy("label", "version"),
    }


def main():
    chemin = f"{DOSSIER_SORTIE}/flux"
    if not os.path.isdir(chemin):
        sys.exit(f"Aucune donnée dans {chemin}. Lancez d'abord le pipeline (docker compose up -d).")

    spark = creer_session("ids-reseau-analyse", avec_kafka=False)
    flux = spark.read.parquet(chemin).dropDuplicates(["_id"]).cache()
    print(f"Flux propres : {flux.count():,}".replace(",", " "))
    alertes = lire_alertes()
    print(f"Alertes temps réel : {len(alertes)}")

    resultats = {
        **calculer_stats(flux),                         # API DataFrame
        **calculer_stats_rdd(spark, flux),              # RDD
        **calculer_stats_sql(spark, flux, alertes),     # SparkSQL + évaluation des alertes live
        **comparer_versions(spark, flux),               # règles v1 vs v2
    }
    for nom, df in resultats.items():
        print(f"\n===== {nom} =====")
        df.show(15, truncate=False)
        ecrire_mongo(df, nom, mode="replace")
        df.coalesce(1).write.mode("overwrite").option("header", True) \
            .csv(f"{DOSSIER_SORTIE}/rapports/{nom}")

    print(f"\nRésultats enregistrés dans MongoDB (collections stats_*) "
          f"et en CSV dans {DOSSIER_SORTIE}/rapports")
    spark.stop()


if __name__ == "__main__":
    main()
