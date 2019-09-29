#!/usr/bin/env bash

export SCRIPTPATH="$(dirname "$(readlink -f "$0")")"
export PROJECTDIR="$(basename ${SCRIPTPATH})"

pushd "${SCRIPTPATH}"/src &> /dev/null
docker kill "${PROJECTDIR}" &> /dev/null

set -e

docker build -t "${PROJECTDIR}":dev -f ../"${PROJECTDIR}".Dockerfile .

echo
echo "Running ${PROJECTDIR}..."
echo

docker run --rm --name "${PROJECTDIR}" -p 8000:8000 -p 8080:8080 -p 5001:5001 "${PROJECTDIR}":dev

echo
