#!/usr/bin/env bash

export SCRIPTPATH="$(dirname "$(readlink -f "$0")")"
export PROJECTDIR="$(basename ${SCRIPTPATH})"

pushd "${SCRIPTPATH}"/src &> /dev/null
docker kill pagesaver &> /dev/null

set -e

docker build -t pagesaver:dev -f ../pagesaver.Dockerfile .

echo
echo "Running pagesaver..."
echo

docker run --rm --name pagesaver -p 8000:8000 -p 8080:8080 -p 5001:5001 pagesaver:dev

echo
