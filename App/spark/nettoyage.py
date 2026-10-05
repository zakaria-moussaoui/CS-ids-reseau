"""
Règles de nettoyage et d'enrichissement des flux réseau CIC-IDS2017.

Entrée : DataFrame brut (tout en texte, tel qu'envoyé par la sonde)
Sortie : flux propres, typés, enrichis (service, protocole, IP privée/publique, sens du trafic)
"""

from pyspark.sql import DataFrame, functions as F, types as T

COLONNES_BRUTES = [
    "Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port",
    "Protocol", "Timestamp", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Flow Bytes/s",
    "Flow Packets/s", "SYN Flag Count", "RST Flag Count", "Label", "capture_ts",
]
SCHEMA_BRUT = T.StructType([T.StructField(c, T.StringType()) for c in COLONNES_BRUTES])

# 1) Filtrage et renommage des champs
RENOMMAGE = {
    "Flow ID": "flow_id",
    "Source IP": "ip_src",
    "Source Port": "port_src",
    "Destination IP": "ip_dst",
    "Destination Port": "port_dst",
    "Protocol": "protocole",
    "Timestamp": "horodatage_brut",
    "Flow Duration": "duree_us",
    "Total Fwd Packets": "paquets_aller",
    "Total Backward Packets": "paquets_retour",
    "Total Length of Fwd Packets": "octets_aller",
    "Total Length of Bwd Packets": "octets_retour",
    "Flow Bytes/s": "debit_octets_brut",
    "Flow Packets/s": "debit_paquets_brut",
    "SYN Flag Count": "flags_syn",
    "RST Flag Count": "flags_rst",
    "Label": "label_brut",
    "capture_ts": "capture_ts",
}
COLONNES_ENTIERES = ["port_src", "port_dst", "protocole", "duree_us", "paquets_aller",
                     "paquets_retour", "octets_aller", "octets_retour", "flags_syn", "flags_rst"]

# Formats de date rencontrés dans CIC-IDS2017 (selon le jour de capture)
FORMATS_DATE = ["d/M/yyyy h:mm:ss a", "d/M/yyyy H:mm:ss", "d/M/yyyy H:mm",
                "dd/MM/yyyy HH:mm:ss", "yyyy-MM-dd HH:mm:ss"]

PROTOCOLES = {0: "HOPOPT", 1: "ICMP", 6: "TCP", 17: "UDP"}

SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS", 67: "DHCP",
    68: "DHCP", 80: "HTTP", 88: "KERBEROS", 110: "POP3", 123: "NTP", 135: "MSRPC",
    137: "NETBIOS", 138: "NETBIOS", 139: "NETBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 993: "IMAPS", 995: "POP3S", 1900: "SSDP",
    3268: "LDAP-GC", 3306: "MYSQL", 3389: "RDP", 5353: "MDNS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
}

REGEX_IPV4 = r"^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$"
REGEX_IP_PRIVEE = r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.)"
VALEURS_INVALIDES = ["INFINITY", "-INFINITY", "INF", "-INF", "NAN"]


def _mapper(colonne, dictionnaire, defaut):
    expr = F.lit(defaut)
    for cle, valeur in dictionnaire.items():
        expr = F.when(colonne == cle, valeur).otherwise(expr)
    return expr


def _type_ip(col):
    return F.when(col.rlike(REGEX_IP_PRIVEE), "privée").otherwise("publique")


def preparer(df: DataFrame) -> DataFrame:
    """Sélection, nettoyage du texte, typage et correction des valeurs."""
    df = df.select([F.col(f"`{brut}`").alias(propre) for brut, propre in RENOMMAGE.items()])

    for c in df.columns:   # espaces supprimés, chaînes vides -> null
        texte = F.trim(F.col(c))
        df = df.withColumn(c, F.when(texte.isin("", "nan", "None", "null"), None).otherwise(texte))

    for c in COLONNES_ENTIERES:   # typage tolérant : valeur illisible -> null
        df = df.withColumn(c, F.expr(f"try_cast(try_cast({c} AS DOUBLE) AS BIGINT)"))

    # Débits : "Infinity" / "NaN" (division par une durée nulle dans CICFlowMeter) -> marqués
    df = df.withColumn("debit_invalide",
                       F.upper("debit_octets_brut").isin(VALEURS_INVALIDES)
                       | F.upper("debit_paquets_brut").isin(VALEURS_INVALIDES)
                       | F.col("debit_octets_brut").isNull())

    # Horodatage : certains fichiers sont en format 12 h SANS AM/PM ("7/7/2017 3:30" = 15h30).
    # La capture a eu lieu entre 8 h et 18 h : une heure < 8 est donc une heure de l'après-midi.
    ts = F.coalesce(*[F.try_to_timestamp(F.col("horodatage_brut"), F.lit(f)) for f in FORMATS_DATE])
    df = (df.withColumn("_ts", ts)
            .withColumn("horodatage_corrige", F.hour("_ts") < 8)
            .withColumn("date_flux", F.when(F.col("horodatage_corrige"),
                                            F.col("_ts") + F.expr("INTERVAL 12 HOURS"))
                                      .otherwise(F.col("_ts")))
            .drop("_ts"))

    # Libellé : "BENIGN" -> "NORMAL", caractères mal encodés ("Web Attack � Brute Force") -> "-"
    label = F.regexp_replace(F.upper("label_brut"), r"[^A-Z0-9 ]", "-")
    label = F.trim(F.regexp_replace(label, r"\s+", " "))
    df = df.withColumn("label", F.when(label == "BENIGN", "NORMAL").otherwise(label))

    return (
        df
        .withColumn("capture_ts", F.try_to_timestamp("capture_ts"))
        .withColumn("est_attaque", F.col("label") != "NORMAL")
        .withColumn("total_paquets", F.col("paquets_aller") + F.col("paquets_retour"))
        .withColumn("total_octets", F.col("octets_aller") + F.col("octets_retour"))
    )


def condition_valide():
    """Un flux est valide si ses champs réseau essentiels sont présents et cohérents."""
    port_ok = lambda c: F.col(c).isNotNull() & F.col(c).between(0, 65535)
    return (
        F.col("ip_src").rlike(REGEX_IPV4) & F.col("ip_dst").rlike(REGEX_IPV4)
        & port_ok("port_src") & port_ok("port_dst")
        & F.col("protocole").isin(list(PROTOCOLES))
        & F.col("date_flux").isNotNull()
        & F.col("label").isNotNull()
        & F.col("duree_us").isNotNull() & (F.col("duree_us") >= 0)
        & (F.col("paquets_aller") >= 0) & (F.col("paquets_retour") >= 0)
        & (F.col("total_paquets") > 0)
        & (F.col("octets_aller") >= 0) & (F.col("octets_retour") >= 0)
    )


def enrichir(df: DataFrame) -> DataFrame:
    """Colonnes calculées (vocabulaire réseau) + identifiant unique pour les doublons."""
    duree_s = F.col("duree_us") / 1_000_000
    sens = (F.when((F.col("ip_src_type") == "privée") & (F.col("ip_dst_type") == "privée"), "interne")
             .when(F.col("ip_src_type") == "privée", "sortant")
             .when(F.col("ip_dst_type") == "privée", "entrant")
             .otherwise("externe"))
    service = _mapper(F.col("port_dst"), SERVICES, None)
    service = F.coalesce(service,
                         F.when(F.col("port_dst") < 1024, "AUTRE-SYSTEME")
                          .when(F.col("port_dst") < 49152, "AUTRE-ENREGISTRE")
                          .otherwise("EPHEMERE"))
    return (
        df
        .withColumn("protocole_nom", _mapper(F.col("protocole"), PROTOCOLES, "AUTRE"))
        .withColumn("service", service)
        .withColumn("ip_src_type", _type_ip(F.col("ip_src")))
        .withColumn("ip_dst_type", _type_ip(F.col("ip_dst")))
        .withColumn("sens", sens)
        # Débits RECALCULÉS à partir des octets et de la durée (au lieu des colonnes corrompues)
        .withColumn("debit_octets_s", F.when(F.col("duree_us") > 0,
                                             F.round(F.col("total_octets") / duree_s, 2)))
        .withColumn("debit_paquets_s", F.when(F.col("duree_us") > 0,
                                              F.round(F.col("total_paquets") / duree_s, 2)))
        .withColumn("duree_ms", F.round(F.col("duree_us") / 1000, 3))
        .withColumn("jour", F.date_format("date_flux", "yyyy-MM-dd"))
        .withColumn("heure", F.hour("date_flux"))
        .withColumn("_id", F.sha2(F.concat_ws("|", "flow_id", "horodatage_brut", "port_src",
                                              "duree_us", "paquets_aller", "paquets_retour",
                                              "octets_aller", "octets_retour", "label"), 256))
        .drop("debit_octets_brut", "debit_paquets_brut", "label_brut")
    )


def nettoyer(df_brut: DataFrame):
    """Renvoie (flux_prepares, flux_valides, flux_propres_sans_doublons)."""
    prepares = preparer(df_brut)
    valides = enrichir(prepares.filter(condition_valide()))
    return prepares, valides, valides.dropDuplicates(["_id"])
