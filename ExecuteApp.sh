#!/usr/bin/env bash
# ============================================================================
#  ExecuteApp.sh — lance le pipeline de détection d'intrusions réseau
#
#  Utilisation (bash ExecuteApp.sh ... fonctionne aussi) :
#    ./ExecuteApp.sh            démarre tout (build des images si besoin)
#    ./ExecuteApp.sh test       démarre avec le petit échantillon de test
#    ./ExecuteApp.sh analyse    lance l'analyse Spark + l'évaluation du détecteur
#    ./ExecuteApp.sh etat       affiche l'état des conteneurs et la progression
#    ./ExecuteApp.sh stop       arrête tout (les données sont conservées)
#    ./ExecuteApp.sh reset      arrête tout et efface les données (Kafka, MongoDB, résultats)
#
#  Sous Windows : à lancer dans Git Bash, ou utiliser ExecuteApp.bat
# ============================================================================
set -e
cd "$(dirname "$0")"

VERT="\033[32m"; ROUGE="\033[31m"; JAUNE="\033[33m"; FIN="\033[0m"
info()   { echo -e "${VERT}▶ $*${FIN}"; }
alerte() { echo -e "${JAUNE}⚠ $*${FIN}"; }
erreur() { echo -e "${ROUGE}✖ $*${FIN}"; exit 1; }

verifier_docker() {
  command -v docker >/dev/null 2>&1 || erreur "Docker n'est pas installé."
  docker info >/dev/null 2>&1 || erreur "Docker ne répond pas : lancez Docker Desktop (« Engine running »)."
}

verifier_dataset() {
  if ls Dataset/Friday-*PortScan*.csv >/dev/null 2>&1 && ls Dataset/Friday-*DDos*.csv >/dev/null 2>&1; then
    info "Dataset CIC-IDS2017 trouvé dans Dataset/"
  else
    alerte "Fichiers CIC-IDS2017 absents de Dataset/ (voir README)."
    alerte "Lancement avec l'échantillon de test : ./ExecuteApp.sh test"
    exec bash "$0" test
  fi
}

demarrer() {
  mkdir -p resultats
  chmod -R a+rwX resultats 2>/dev/null || true   # Spark (utilisateur 1000 du conteneur) doit pouvoir écrire
  if [ -d resultats/checkpoints ]; then
    alerte "Le trafic a déjà été traité (resultats/checkpoints existe)."
    alerte "Démarrage en mode consultation : MongoDB + Mini-SOC seulement."
    alerte "Pour tout rejouer depuis le début : ./ExecuteApp.sh reset   puis   ./ExecuteApp.sh"
    docker compose up -d mongodb dashboard
    echo "   • Mini-SOC : http://localhost:8501"
    return
  fi
  info "Construction des images et démarrage des conteneurs..."
  docker compose up -d --build
  echo
  info "Pipeline démarré !"
  echo "   • Mini-SOC (tableau de bord) : http://localhost:8501"
  echo "   • Interface Spark            : http://localhost:4040"
  echo "   • Suivre les alertes         : docker compose logs -f spark-streaming"
  echo "   • Quand tout est traité      : ./ExecuteApp.sh analyse"
}

case "${1:-start}" in
  start)
    verifier_docker
    verifier_dataset
    export FICHIERS="/data/Friday-*PortScan*.csv,/data/Friday-*DDos*.csv"
    demarrer
    ;;
  test)
    verifier_docker
    info "Mode test : échantillon Dataset/echantillon_reseau_test.csv (17 370 flux générés)"
    export FICHIERS="/data/echantillon_reseau_test.csv"
    demarrer
    ;;
  analyse)
    verifier_docker
    if [ "$(docker inspect -f '{{.State.Running}}' ids-producer 2>/dev/null)" = "true" ]; then
      alerte "La sonde envoie encore des flux : le traitement n'est pas terminé."
      alerte "Patientez, puis vérifiez avec : ./ExecuteApp.sh etat   (la sonde doit être « Exited »)"
      exit 1
    fi
    if [ ! -d resultats/flux ]; then
      erreur "Aucun résultat dans resultats/flux : lancez d'abord ./ExecuteApp.sh et attendez la fin du traitement."
    fi
    info "Arrêt du streaming et de Kafka pour libérer la mémoire..."
    docker compose stop spark-streaming kafka dashboard
    info "Analyse Spark (DataFrame, RDD, SparkSQL) + évaluation du détecteur v1 / v2..."
    docker compose run --rm spark-analytics
    info "Redémarrage du tableau de bord..."
    docker compose start dashboard
    echo "   • Résultats : MongoDB (collections stats_*) et resultats/rapports/ (CSV)"
    ;;
  etat)
    docker compose ps -a
    if [ "$(docker inspect -f '{{.State.Running}}' ids-producer 2>/dev/null)" = "true" ]; then
      echo "Sonde : envoi des flux EN COURS (attendez avant ./ExecuteApp.sh analyse)"
    else
      echo "Sonde : envoi TERMINÉ"
    fi
    echo
    docker exec ids-mongodb mongosh ids_reseau --quiet --eval '
      const j = db.journal_nettoyage.aggregate([{$group:{_id:null, recus:{$sum:"$flux_recus"},
        propres:{$sum:"$flux_valides"}, attaques:{$sum:"$flux_attaques"}}}]).toArray()[0] || {};
      print("Flux reçus : " + (j.recus||0) + " | propres : " + (j.propres||0) +
            " | malveillants : " + (j.attaques||0) + " | alertes : " + db.alertes.countDocuments());' \
      2>/dev/null || alerte "MongoDB n'est pas démarré."
    ;;
  stop)
    info "Arrêt de tous les conteneurs (données conservées)..."
    docker compose down
    ;;
  reset)
    alerte "Suppression des données Kafka, MongoDB et des résultats..."
    docker compose down -v
    rm -rf resultats/flux resultats/rapports resultats/checkpoints
    info "Projet remis à zéro."
    ;;
  *)
    echo "Usage : ./ExecuteApp.sh [start | test | analyse | etat | stop | reset]"
    exit 1
    ;;
esac
