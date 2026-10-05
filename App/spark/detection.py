"""
Détection d'intrusions EN TEMPS RÉEL avec Spark Structured Streaming.

Les flux sont regroupés par fenêtre de temps (1 minute, sur l'heure réelle du flux) et par
couple (IP source -> IP destination). Règles inspirées des IDS (Snort, Suricata).

Deux versions des règles existent (variable VERSION_REGLES, v2 par défaut) :

  v1 (naïve)
    SCAN DE PORTS : >= SEUIL_SCAN ports différents (< 10 000) d'une même cible
    FLOOD / DDOS  : >= SEUIL_FLOOD flux vers une même cible
    BRUTE FORCE   : >= SEUIL_BRUTEFORCE connexions vers SSH (22) / FTP (21)

  v2 (après analyse des fausses alertes de la v1 sur CIC-IDS2017)
    FLOOD / DDOS  : on ne compte que les flux vers un PORT DE SERVICE (< 1024)
                    -> les réponses du serveur (flux inversés vers un port éphémère) ne comptent plus
                    + LISTE BLANCHE des serveurs d'infrastructure (DNS / contrôleur de domaine)
    BRUTE FORCE   : les connexions SSH/FTP doivent être CONCENTRÉES (< 20 ports différents)
                    -> un scan qui touche aussi 21/22 n'est plus appelé « brute force »
    SCAN DE PORTS : inchangé (100 % de précision en v1)

Le « watermark » indique à Spark jusqu'à quand attendre des flux en retard, puis il libère
la mémoire des anciennes fenêtres.
"""

import os
from datetime import datetime, timezone

from pyspark.sql import functions as F

from nettoyage import condition_valide, preparer

FENETRE = os.getenv("FENETRE", "1 minute")
WATERMARK = os.getenv("WATERMARK", "1 hour")
SEUIL_SCAN = int(os.getenv("SEUIL_SCAN", "100"))
SEUIL_FLOOD = int(os.getenv("SEUIL_FLOOD", "1000"))
SEUIL_BRUTEFORCE = int(os.getenv("SEUIL_BRUTEFORCE", "30"))
PORTS_MAX_BRUTEFORCE = int(os.getenv("PORTS_MAX_BRUTEFORCE", "20"))
# Serveurs d'infrastructure connus (CIC-IDS2017 : 192.168.10.3 = DNS / contrôleur de domaine)
LISTE_BLANCHE = [ip.strip() for ip in os.getenv("LISTE_BLANCHE", "192.168.10.3").split(",") if ip.strip()]
VERSION_REGLES = os.getenv("VERSION_REGLES", "v2")

# Chaque règle : type, gravité, mesure principale, seuil, condition, description
REGLES_PAR_VERSION = {
    "v1": [
        ("SCAN DE PORTS", "MOYENNE", "ports_distincts", SEUIL_SCAN, lambda l: True,
         "{ip_src} a sondé {valeur} ports différents de {ip_dst} en {fenetre}"),
        ("FLOOD / DDOS", "CRITIQUE", "nb_flux", SEUIL_FLOOD, lambda l: True,
         "{ip_src} a envoyé {valeur} flux vers {ip_dst} en {fenetre}"),
        ("BRUTE FORCE SSH/FTP", "HAUTE", "connexions_ssh_ftp", SEUIL_BRUTEFORCE, lambda l: True,
         "{ip_src} a tenté {valeur} connexions SSH/FTP vers {ip_dst} en {fenetre}"),
    ],
    "v2": [
        ("SCAN DE PORTS", "MOYENNE", "ports_distincts", SEUIL_SCAN, lambda l: True,
         "{ip_src} a sondé {valeur} ports différents de {ip_dst} en {fenetre}"),
        ("FLOOD / DDOS", "CRITIQUE", "flux_vers_service", SEUIL_FLOOD, lambda l: True,
         "{ip_src} a envoyé {valeur} flux vers les services de {ip_dst} en {fenetre}"),
        ("BRUTE FORCE SSH/FTP", "HAUTE", "connexions_ssh_ftp", SEUIL_BRUTEFORCE,
         lambda l: l["ports_distincts"] < PORTS_MAX_BRUTEFORCE,
         "{ip_src} a tenté {valeur} connexions SSH/FTP vers {ip_dst} en {fenetre}"),
    ],
}
REGLES = REGLES_PAR_VERSION[VERSION_REGLES]


def agreger_fenetres_propres(flux):
    """Agrégation par fenêtre de temps, sur des flux déjà nettoyés.
    Fonctionne en STREAMING (état gardé en mémoire par Spark) comme en BATCH (Parquet)."""
    service = (F.col("port_dst") < 1024) & ~F.col("ip_dst").isin(LISTE_BLANCHE)
    return (
        flux.select("date_flux", "ip_src", "ip_dst", "port_dst")
        .withWatermark("date_flux", WATERMARK)
        .groupBy(F.window("date_flux", FENETRE).alias("fenetre"), "ip_src", "ip_dst")
        .agg(
            F.count("*").alias("nb_flux"),
            F.sum(F.when(service, 1).otherwise(0)).alias("flux_vers_service"),
            # approx_count_distinct (HyperLogLog) : le comptage exact n'existe pas en streaming
            F.approx_count_distinct(F.when(F.col("port_dst") < 10000, F.col("port_dst")))
             .alias("ports_distincts"),
            F.sum(F.when(F.col("port_dst").isin(21, 22), 1).otherwise(0)).alias("connexions_ssh_ftp"),
        )
    )


def agreger_fenetres(flux_bruts):
    """Version streaming : nettoyage à la volée puis agrégation."""
    return agreger_fenetres_propres(preparer(flux_bruts).filter(condition_valide()))


def filtre_candidates():
    """Fenêtres qui dépassent au moins un seuil (toutes versions confondues)."""
    return ((F.col("ports_distincts") >= SEUIL_SCAN) | (F.col("nb_flux") >= SEUIL_FLOOD)
            | (F.col("flux_vers_service") >= SEUIL_FLOOD)
            | (F.col("connexions_ssh_ftp") >= SEUIL_BRUTEFORCE))


def construire_alertes(lignes, version=VERSION_REGLES):
    """Transforme les fenêtres agrégées en alertes (documents MongoDB)."""
    regles = REGLES_PAR_VERSION[version]
    alertes = []
    for l in lignes:
        for type_, gravite, mesure, seuil, condition, texte in regles:
            valeur = l[mesure]
            if valeur is None or valeur < seuil or not condition(l):
                continue
            debut, fin = l["fenetre"]["start"], l["fenetre"]["end"]
            alertes.append({
                "_id": f"{type_}|{l['ip_src']}|{l['ip_dst']}|{debut.isoformat()}",
                "type": type_,
                "gravite": gravite,
                "ip_src": l["ip_src"],
                "ip_dst": l["ip_dst"],
                "debut_fenetre": debut,
                "fin_fenetre": fin,
                "mesure": mesure,
                "valeur": int(valeur),
                "seuil": seuil,
                "nb_flux": int(l["nb_flux"]),
                "flux_vers_service": int(l["flux_vers_service"]),
                "ports_distincts": int(l["ports_distincts"]),
                "connexions_ssh_ftp": int(l["connexions_ssh_ftp"]),
                "version_regles": version,
                "description": texte.format(ip_src=l["ip_src"], ip_dst=l["ip_dst"],
                                            valeur=int(valeur), fenetre=FENETRE),
            })
    return alertes


def traiter_fenetres(df_fenetres, batch_id, ecrire_alertes):
    """Appelé à chaque micro-batch : seules les fenêtres mises à jour arrivent ici."""
    candidates = df_fenetres.filter(filtre_candidates()).collect()   # peu de lignes
    alertes = construire_alertes(candidates)
    if alertes:
        ecrire_alertes(alertes, datetime.now(timezone.utc))
        for a in alertes:
            print(f"🚨 [{a['gravite']}] {a['type']} : {a['description']}", flush=True)
