#!/bin/sh
set -e
docker start proctool-neo4j || \
docker run \
    --name proctool-neo4j \
    -p7474:7474 -p7687:7687 \
    -d \
    -v $PWD/_db/data:/data \
    -v $PWD/_db/logs:/logs \
    -v $PWD/_db/import:/var/lib/neo4j/import \
    -v $PWD/_db/plugins:/plugins \
    -e NEO4J_AUTH=neo4j/test \
    -e NEO4J_apoc_export_file_enabled=true \
    -e NEO4J_apoc_import_file_enabled=true \
    -e NEO4J_apoc_import_file_use__neo4j__config=true \
    -e NEO4JLABS_PLUGINS=\[\"apoc\"\] \
    neo4j:latest

echo "Browse to http://localhost:7474/browser/ and log in with neo4j/test"
