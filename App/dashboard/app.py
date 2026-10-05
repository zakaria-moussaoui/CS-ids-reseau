"""
Mini-SOC : tableau de bord temps réel de la détection d'intrusions.
Lit MongoDB (journal_nettoyage, alertes, flux) et se rafraîchit toutes les 5 secondes.

http://localhost:8501
"""

import os

import pandas as pd
import streamlit as st
from pymongo import DESCENDING, MongoClient

MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongodb:27017")
MONGO_DB = os.getenv("MONGO_DB", "ids_reseau")
RAFRAICHISSEMENT = int(os.getenv("RAFRAICHISSEMENT", "5"))

ICONES = {"CRITIQUE": "🔴", "HAUTE": "🟠", "MOYENNE": "🟡"}


@st.cache_resource
def base():
    return MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)[MONGO_DB]


def lire_kpis(db):
    res = list(db.journal_nettoyage.aggregate([{"$group": {
        "_id": None,
        "recus": {"$sum": "$flux_recus"},
        "valides": {"$sum": "$flux_valides"},
        "rejetes": {"$sum": "$flux_rejetes"},
        "doublons": {"$sum": "$doublons_supprimes"},
        "attaques": {"$sum": "$flux_attaques"},
        "debits": {"$sum": "$debits_infinis_recalcules"},
        "batchs": {"$sum": 1},
    }}]))
    kpis = res[0] if res else {k: 0 for k in
                               ("recus", "valides", "rejetes", "doublons", "attaques", "debits", "batchs")}
    kpis["alertes"] = db.alertes.count_documents({})
    kpis["critiques"] = db.alertes.count_documents({"gravite": "CRITIQUE"})
    return kpis


def lire_alertes(db, limite=25):
    docs = list(db.alertes.find({}).sort("detectee_le", DESCENDING).limit(limite))
    if not docs:
        return pd.DataFrame()
    df = pd.DataFrame(docs)
    df["gravité"] = df["gravite"].map(lambda g: f"{ICONES.get(g, '⚪')} {g}")
    df = df.rename(columns={"type": "type d'attaque", "ip_src": "source", "ip_dst": "cible",
                            "debut_fenetre": "fenêtre (heure du flux)", "description": "détail",
                            "detectee_le": "détectée le"})
    return df[["détectée le", "gravité", "type d'attaque", "source", "cible",
               "fenêtre (heure du flux)", "détail"]]


@st.cache_data(ttl=30, show_spinner=False)
def lire_chronologie(_db):
    """Flux par minute (heure réelle du flux) : normal vs attaques. Recalculé toutes les 30 s."""
    res = _db.flux.aggregate([
        {"$group": {"_id": {"minute": {"$dateToString": {"format": "%Y-%m-%d %H:%M",
                                                         "date": "$date_flux"}},
                            "attaque": "$est_attaque"},
                    "flux": {"$sum": 1}}},
    ])
    lignes = [{"minute": d["_id"]["minute"],
               "type": "attaques" if d["_id"]["attaque"] else "trafic normal",
               "flux": d["flux"]} for d in res]
    if not lignes:
        return pd.DataFrame()
    df = pd.DataFrame(lignes).pivot_table(index="minute", columns="type", values="flux",
                                          aggfunc="sum", fill_value=0)
    for col in ("trafic normal", "attaques"):
        if col not in df:
            df[col] = 0
    df.index = pd.to_datetime(df.index)
    return df.sort_index()[["trafic normal", "attaques"]]


def lire_labels(db):
    totaux = {}
    for doc in db.journal_nettoyage.find({}, {"par_label": 1}):
        for label, n in (doc.get("par_label") or {}).items():
            totaux[label] = totaux.get(label, 0) + n
    return pd.DataFrame({"type": list(totaux), "flux": list(totaux.values())})


@st.cache_data(ttl=30, show_spinner=False)
def lire_ports_attaques(_db):
    res = _db.flux.aggregate([
        {"$match": {"est_attaque": True}},
        {"$group": {"_id": {"port": "$port_dst", "service": "$service"}, "flux": {"$sum": 1}}},
        {"$sort": {"flux": -1}}, {"$limit": 10},
    ])
    return pd.DataFrame([{"port": f"{d['_id']['port']} ({d['_id']['service']})", "flux": d["flux"]}
                         for d in res])


def barres_triees(df, categorie, couleur, log=False):
    """Barres horizontales triées de la plus grande à la plus petite."""
    import altair as alt
    echelle = alt.Scale(type="log") if log else alt.Scale()
    titre = "flux (échelle logarithmique)" if log else "flux"
    return (alt.Chart(df).mark_bar(color=couleur)
            .encode(x=alt.X("flux:Q", title=titre, scale=echelle),
                    y=alt.Y(f"{categorie}:N", sort="-x", title=None,
                            axis=alt.Axis(labelLimit=220)),
                    tooltip=[categorie, "flux"])
            .properties(height=max(160, 40 * len(df))))


def afficher_temps_reel():
    db = base()
    try:
        k = lire_kpis(db)
    except Exception as e:
        st.error(f"MongoDB inaccessible ({MONGO_URI}) : {e}")
        return

    c = st.columns(6)
    c[0].metric("Flux reçus", f"{k['recus']:,}".replace(",", " "))
    c[1].metric("Flux propres", f"{k['valides']:,}".replace(",", " "))
    c[2].metric("Rejetés / doublons", f"{k['rejetes'] + k['doublons']:,}".replace(",", " "))
    c[3].metric("Flux malveillants", f"{k['attaques']:,}".replace(",", " "),
                f"{100 * k['attaques'] / k['valides']:.1f} %" if k["valides"] else None,
                delta_color="inverse")
    c[4].metric("Alertes", k["alertes"])
    c[5].metric("Alertes critiques", k["critiques"])

    st.subheader("🚨 Dernières alertes")
    alertes = lire_alertes(db)
    if alertes.empty:
        st.info("Aucune alerte pour l'instant. Le réseau est calme… ou le producer n'a pas démarré.")
    else:
        st.dataframe(alertes, use_container_width=True, hide_index=True)

    st.subheader("📈 Chronologie du trafic (flux par minute, heure réelle de la capture)")
    chrono = lire_chronologie(db)
    if not chrono.empty:
        st.area_chart(chrono, color=["#4C9AFF", "#E5484D"])

    gauche, droite = st.columns(2)
    with gauche:
        st.subheader("🏷️ Répartition du trafic")
        labels = lire_labels(db)
        if not labels.empty:
            st.altair_chart(barres_triees(labels, "type", "#4C9AFF"), use_container_width=True)
    with droite:
        st.subheader("🎯 Ports les plus attaqués")
        ports = lire_ports_attaques(db)
        if not ports.empty:
            st.altair_chart(barres_triees(ports, "port", "#E5484D", log=True), use_container_width=True)

    st.caption(f"Mise à jour automatique toutes les {RAFRAICHISSEMENT} s · "
               f"{k['batchs']} micro-batchs traités · "
               f"{k['debits']:,} débits « Infinity » recalculés".replace(",", " "))


st.set_page_config(page_title="Mini-SOC IDS", page_icon="🛡️", layout="wide")
st.title("🛡️ Mini-SOC — Détection d'intrusions en temps réel")
st.caption("Kafka → Spark Structured Streaming → MongoDB · dataset CIC-IDS2017")

if hasattr(st, "fragment"):
    st.fragment(run_every=RAFRAICHISSEMENT)(afficher_temps_reel)()
else:   # anciennes versions de Streamlit
    afficher_temps_reel()
