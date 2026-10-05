@echo off
REM ==========================================================================
REM  ExecuteApp.bat - équivalent Windows de ExecuteApp.sh
REM  Utilisation : ExecuteApp.bat [start | test | analyse | etat | stop | reset]
REM ==========================================================================
chcp 65001 >nul
cd /d "%~dp0"
set ACTION=%1
if "%ACTION%"=="" set ACTION=start

docker info >nul 2>&1
if errorlevel 1 (
  echo Docker ne repond pas : lancez Docker Desktop ^(Engine running^).
  exit /b 1
)

if "%ACTION%"=="start" (
  if not exist "Dataset\Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv" (
    echo Fichiers CIC-IDS2017 absents de Dataset : lancement avec l'echantillon de test.
    goto test
  )
  set FICHIERS=/data/Friday-*PortScan*.csv,/data/Friday-*DDos*.csv
  goto demarrer
)
if "%ACTION%"=="test" goto test
if "%ACTION%"=="analyse" goto analyse
if "%ACTION%"=="etat" goto etat
if "%ACTION%"=="stop" goto stop
if "%ACTION%"=="reset" goto reset
echo Usage : ExecuteApp.bat [start ^| test ^| analyse ^| etat ^| stop ^| reset]
exit /b 1

:test
set FICHIERS=/data/echantillon_reseau_test.csv
echo Mode test : echantillon de 17 370 flux generes.

:demarrer
if not exist resultats mkdir resultats
if exist resultats\checkpoints (
  echo Le trafic a deja ete traite : mode consultation ^(MongoDB + Mini-SOC^).
  echo Pour tout rejouer : ExecuteApp.bat reset   puis   ExecuteApp.bat
  docker compose up -d mongodb dashboard
  echo   - Mini-SOC : http://localhost:8501
  exit /b 0
)
docker compose up -d --build
echo.
echo Pipeline demarre !
echo   - Mini-SOC        : http://localhost:8501
echo   - Interface Spark : http://localhost:4040
echo   - Alertes         : docker compose logs -f spark-streaming
echo   - Ensuite         : ExecuteApp.bat analyse
exit /b 0

:analyse
set SONDE=
for /f %%r in ('docker inspect -f "{{.State.Running}}" ids-producer 2^>nul') do set SONDE=%%r
if "%SONDE%"=="true" (
  echo La sonde envoie encore des flux : le traitement n'est pas termine.
  echo Patientez, puis verifiez avec : ExecuteApp.bat etat   ^(la sonde doit etre "Exited"^)
  exit /b 1
)
if not exist resultats\flux (
  echo Aucun resultat dans resultats\flux : lancez d'abord ExecuteApp.bat et attendez la fin du traitement.
  exit /b 1
)
docker compose stop spark-streaming kafka dashboard
docker compose run --rm spark-analytics
docker compose start dashboard
echo Resultats : MongoDB (collections stats_*) et resultats\rapports\
exit /b 0

:etat
docker compose ps -a
echo.
set SONDE=
for /f %%r in ('docker inspect -f "{{.State.Running}}" ids-producer 2^>nul') do set SONDE=%%r
if "%SONDE%"=="true" (echo Sonde : envoi des flux EN COURS - attendez avant ExecuteApp.bat analyse) else (echo Sonde : envoi TERMINE)
docker exec ids-mongodb mongosh ids_reseau --quiet --eval "const j=db.journal_nettoyage.aggregate([{$group:{_id:null,r:{$sum:'$flux_recus'},a:{$sum:'$flux_attaques'}}}]).toArray()[0]||{}; print('Flux traites par Spark : '+(j.r||0)+'  -  malveillants : '+(j.a||0)+'  -  alertes : '+db.alertes.countDocuments())" 2>nul || echo MongoDB n'est pas demarre : lancez d'abord ExecuteApp.bat
exit /b 0

:stop
docker compose down
exit /b 0

:reset
docker compose down -v
if exist resultats\flux rmdir /s /q resultats\flux
if exist resultats\rapports rmdir /s /q resultats\rapports
if exist resultats\checkpoints rmdir /s /q resultats\checkpoints
echo Projet remis a zero.
exit /b 0
