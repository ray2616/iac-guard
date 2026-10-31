#!/bin/bash
set -euo pipefail
version=v2.39.4
mkdir -p /usr/local/lib/docker/cli-plugins
directory=$(mktemp -d)
trap 'rm -rf "$directory"' EXIT
cd "$directory"
curl --fail --location --retry 3 --output docker-compose-linux-x86_64 "https://github.com/docker/compose/releases/download/$version/docker-compose-linux-x86_64"
curl --fail --location --retry 3 --output checksums.txt "https://github.com/docker/compose/releases/download/$version/checksums.txt"
grep ' docker-compose-linux-x86_64$' checksums.txt | sha256sum --check
install -m 0755 docker-compose-linux-x86_64 /usr/local/lib/docker/cli-plugins/docker-compose
