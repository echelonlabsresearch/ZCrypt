#!/bin/sh
# Start a validator on a fresh Linux box.
#
# Ubuntu's docker.io package ships the old `docker-compose` v1 binary and no
# `docker compose` plugin. v1 rejects this compose file. This script installs
# the Compose v2 plugin if it is missing, pulls the published ABCI image, and
# builds from this checkout only when the pull fails.
set -eu
cd "$(dirname "$0")"

COMPOSE_VERSION=v2.32.4

die() { echo "validator-up: $*" >&2; exit 1; }

compose_ok() {
  docker compose version >/dev/null 2>&1 && return 0
  sudo docker compose version >/dev/null 2>&1
}

install_compose() {
  arch=$(uname -m)
  case "$arch" in
    x86_64|aarch64) ;;
    arm64) arch=aarch64 ;;
    *) die "no Compose binary for architecture $arch" ;;
  esac
  url="https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-${arch}"
  tmp=$(mktemp)
  echo "validator-up: installing Docker Compose ${COMPOSE_VERSION}"
  curl -fsSL "$url" -o "$tmp"
  chmod +x "$tmp"
  if docker info >/dev/null 2>&1; then
    mkdir -p "$HOME/.docker/cli-plugins"
    mv "$tmp" "$HOME/.docker/cli-plugins/docker-compose"
  else
    sudo mkdir -p /usr/local/lib/docker/cli-plugins
    sudo mv "$tmp" /usr/local/lib/docker/cli-plugins/docker-compose
  fi
}

dc() {
  if docker info >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  else
    sudo docker compose "$@"
  fi
}

command -v docker >/dev/null 2>&1 || die "install Docker first (docker.io or Docker Engine)"
compose_ok || install_compose
compose_ok || die "Docker Compose v2 is still not available. Install the docker-compose-plugin package."

if dc -f docker-compose.validator.yml pull validator-abci; then
  dc -f docker-compose.validator.yml up -d
else
  echo "validator-up: published image is not pullable yet. Building zcrypt-abci:local from this checkout."
  echo "validator-up: the first build compiles Rust and takes a long time."
  envfile=$(mktemp)
  if [ -f .env ]; then
    grep -v '^ZCRYPT_ABCI_IMAGE=' .env > "$envfile" || true
  fi
  printf '%s\n' 'ZCRYPT_ABCI_IMAGE=zcrypt-abci:local' >> "$envfile"
  dc --env-file "$envfile" \
    -f docker-compose.validator.yml \
    -f docker-compose.validator.build.yml \
    up -d --build
  rm -f "$envfile"
fi

echo "validator-up: running. Follow sync with: docker logs -f zcrypt-validator-cometbft"
