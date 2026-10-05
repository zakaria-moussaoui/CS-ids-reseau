Name : Détection d'intrusions réseau en temps réel

1. Objectif

Construire un pipeline Big Data qui :
- récupère du trafic réseau réel.
- le nettoie.
- détecte les attaques en temps réel (scan de ports, DDoS, brute force).
- stocke les résultats dans une base de données.

Le tout tourne dans Docker, avec un tableau de bord qui affiche les alertes en direct.


2. Dataset

- Nom : CIC-IDS2017
- Source : Canadian Institute for Cybersecurity, Université du Nouveau-Brunswick (Canada)
- Lien : https://www.unb.ca/cic/datasets/ids-2017.html
- Fichier à télécharger : GeneratedLabelledFlows.zip, dossier TrafficLabelling
- Fichiers utilisés :
  - Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
  - Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
- Contenu : 512 212 flux réseau réels (IP, ports, protocole, durée, paquets, octets),
  chacun avec un label : BENIGN, PortScan ou DDoS

Remarque : si ces fichiers ne sont pas dans le dossier Dataset/, le projet utilise
automatiquement echantillon_reseau_test.csv, un petit échantillon de test généré au même format.


3. Architecture

```
CSV (CIC-IDS2017)
      |
      v
Producer Python  -->  Kafka  -->  Spark Streaming  -->  MongoDB + Parquet
  (extraction)                    (nettoyage +               |
                                   détection)                v
                                                     Tableau de bord
                                                     (localhost:8501)
```

- Python (producer) : lit les CSV et envoie chaque flux dans Kafka, comme en temps réel.
- Kafka : transporte les flux jusqu'à Spark.
- Spark Streaming (PySpark) : nettoie les flux et détecte les attaques, toutes les 10 secondes.
- MongoDB : stocke les flux propres, les alertes et les statistiques.
- Parquet : stocke les flux propres pour l'analyse (dossier resultats).
- Streamlit : tableau de bord des alertes.
- Docker : lance tous les services ensemble.


4. Traitement

Nettoyage :
- garder seulement les 17 colonnes utiles sur 85.
- supprimer les lignes avec des valeurs null (IP, port, date...).
- remplacer les valeurs Infinity / NaN par un débit recalculé.
- corriger l'heure (format 12 h sans AM/PM : 3:56 devient 15:56).
- supprimer les IP invalides, les ports hors limites et les valeurs négatives.
- supprimer les doublons.
- ajouter des informations utiles : service (22 = SSH, 80 = HTTP...), TCP/UDP, IP privée ou publique.

Détection des attaques (par minute, d'une même source vers une même cible) :
- Scan de ports : 100 ports différents ou plus.
- DDoS : 1 000 flux ou plus.
- Brute force SSH/FTP : 30 connexions ou plus vers les ports 21/22.

Analyse (Spark DataFrame, RDD et SparkSQL) :
répartition des attaques, ports les plus visés, machines attaquantes, précision des alertes.

Résultats : 512 212 flux traités, 56 % de trafic malveillant, 36 alertes, toutes justes.


5. Lancement du projet

Prérequis : Docker Desktop démarré.

| Étape | macOS / Linux | Windows |
|---|---|---|
| 1. Démarrer le projet | bash ExecuteApp.sh | ExecuteApp.bat |
| 2. Voir les alertes | http://localhost:8501 | http://localhost:8501 |
| 3. Suivre la progression | bash ExecuteApp.sh etat | ExecuteApp.bat etat |
| 4. Lancer l'analyse (quand l'envoi est terminé) | bash ExecuteApp.sh analyse | ExecuteApp.bat analyse |
| 5. Arrêter le projet | bash ExecuteApp.sh stop | ExecuteApp.bat stop |
| 6. Tout remettre à zéro | bash ExecuteApp.sh reset | ExecuteApp.bat reset |

Remarque : au premier lancement, Docker télécharge environ 3 Go d'images (comptez 10 à 30 minutes).
