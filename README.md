# Fake Open AM
Returnerer JWT for oppgitt bruker

## Kjøre 
`mvn quarkus:dev`

## Pakke
`mvn package`

`docker build -f src/main/docker/Dockerfile.jvm -t nvdbapnevegdata/fake-openam-oidc .`

`docker push nvdbapnevegdata/fake-openam-oidc:latest`

