"""Écriture dans MongoDB avec pymongo (avec réessais si MongoDB est momentanément indisponible)."""

import time

from config import MONGO_DB, MONGO_URI

TENTATIVES = 5


def avec_reessais(action, description):
    """Exécute action() ; en cas de coupure avec MongoDB, attend puis réessaie."""
    from pymongo.errors import BulkWriteError, PyMongoError
    for essai in range(1, TENTATIVES + 1):
        try:
            return action()
        except BulkWriteError:
            raise   # vraie erreur de données : inutile de réessayer
        except PyMongoError as e:
            if essai == TENTATIVES:
                raise
            attente = 5 * essai
            print(f"⚠️ MongoDB indisponible ({description}, essai {essai}/{TENTATIVES}) : "
                  f"{type(e).__name__}. Nouvel essai dans {attente} s", flush=True)
            time.sleep(attente)


def ecrire_lignes(lignes, uri, base, collection, mode, taille_lot=1000):
    """Écrit des lignes Spark (Row) dans une collection.
    mode="upsert" : remplace le document de même _id (pas de doublons) ; "insert" : ajout simple.
    Les upserts peuvent être rejoués sans risque après une coupure."""
    from pymongo import InsertOne, MongoClient, ReplaceOne

    client = MongoClient(uri, socketTimeoutMS=120_000, connectTimeoutMS=30_000,
                         serverSelectionTimeoutMS=60_000)
    col = client[base][collection]

    def envoyer(lot):
        avec_reessais(lambda: col.bulk_write(lot, ordered=False), f"écriture {collection}")

    lot = []
    for ligne in lignes:
        doc = ligne.asDict() if hasattr(ligne, "asDict") else dict(ligne)
        lot.append(ReplaceOne({"_id": doc["_id"]}, doc, upsert=True) if mode == "upsert"
                   else InsertOne(doc))
        if len(lot) >= taille_lot:
            envoyer(lot)
            lot = []
    if lot:
        envoyer(lot)
    client.close()


def ecrire_mongo(df, collection, mode="upsert"):
    """Écriture distribuée (une connexion par partition Spark).
    mode="replace" : vide la collection puis insère (résultats d'analyse)."""
    uri, base = MONGO_URI, MONGO_DB
    if mode == "replace":
        from pymongo import MongoClient
        with MongoClient(uri) as client:
            client[base][collection].drop()
        mode = "insert"
    df.foreachPartition(lambda lignes: ecrire_lignes(lignes, uri, base, collection, mode))


def ecrire_alertes(alertes, maintenant):
    """Upsert des alertes : 'detectee_le' garde la date de PREMIÈRE détection,
    les compteurs sont mis à jour tant que la fenêtre de temps reçoit des flux."""
    from pymongo import MongoClient, UpdateOne
    ops = []
    for a in alertes:
        a = dict(a)
        _id = a.pop("_id")
        ops.append(UpdateOne({"_id": _id},
                             {"$set": {**a, "mise_a_jour_le": maintenant},
                              "$setOnInsert": {"detectee_le": maintenant}},
                             upsert=True))
    with MongoClient(MONGO_URI, serverSelectionTimeoutMS=60_000) as client:
        avec_reessais(lambda: client[MONGO_DB]["alertes"].bulk_write(ops, ordered=False),
                      "écriture alertes")


def journaliser(entree):
    from pymongo import MongoClient
    with MongoClient(MONGO_URI, serverSelectionTimeoutMS=60_000) as client:
        # upsert sur batch_id : si un batch est rejoué après une panne, il n'est pas compté 2 fois
        avec_reessais(lambda: client[MONGO_DB]["journal_nettoyage"].replace_one(
            {"batch_id": entree["batch_id"]}, entree, upsert=True), "journal")


def creer_index():
    from pymongo import MongoClient
    with MongoClient(MONGO_URI) as client:
        db = client[MONGO_DB]
        for champ in ("ip_src", "ip_dst", "port_dst", "label", "est_attaque", "date_flux"):
            db["flux"].create_index(champ)
        db["alertes"].create_index("detectee_le")
        db["alertes"].create_index("type")
        db["journal_nettoyage"].create_index("batch_id")


def lire_alertes():
    from pymongo import MongoClient
    with MongoClient(MONGO_URI) as client:
        return list(client[MONGO_DB]["alertes"].find({}))
