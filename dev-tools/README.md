# dev-tools

Esta carpeta contiene el pipeline de DevSecOps completo que existió en versiones anteriores del proyecto: Jenkins, SonarQube autoalojado y OWASP ZAP (DAST). Fue eliminada del repositorio en un commit anterior y se recuperó desde el historial de git para esta entrega.

## Estado actual

Ninguno de estos componentes se ejecuta automáticamente. El único pipeline activo hoy es `.github/workflows/sonar.yml`, que corre en cada push o pull request a `main` y solo ejecuta las pruebas del backend más el análisis de SonarCloud.

Lo que hay en esta carpeta está disponible para revisar, reparar y activar progresivamente:

- `jenkins/`: imagen de Jenkins con Docker CLI, `Jenkinsfile` con las etapas de tests de backend y frontend, SAST con SonarQube, Quality Gate, y DAST con OWASP ZAP contra la API y el frontend.
- `sonarqube/`: SonarQube autoalojado (no SonarCloud) con su propia base de datos Postgres.
- `zap/`: una configuración alternativa de OWASP ZAP en modo baseline.

## Antes de activar cualquier cosa

Ningún componente aquí fue verificado para esta entrega. Al menos el `docker-compose.yml` de `zap/` tiene una ruta de volumen absoluta que pertenece a otra máquina (`/home/fabian/...`) y no va a funcionar sin corregirla. Es esperable encontrar más de este tipo de problemas al intentar levantar Jenkins o SonarQube autoalojado.
