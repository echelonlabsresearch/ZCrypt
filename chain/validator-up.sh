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

# The testnet branch is mainnet code that has not shipped. Its image tag is :testnet.
# The mainnet branch pulls :mainnet. A ZCRYPT_ABCI_IMAGE in the shell or .env wins.
image_ref() {
  if [ -n "${ZCRYPT_ABCI_IMAGE:-}" ]; then
    printf '%s\n' "$ZCRYPT_ABCI_IMAGE"
    return
  fi
  if [ -f .env ]; then
    val=$(grep -E '^ZCRYPT_ABCI_IMAGE=' .env | tail -1 | cut -d= -f2- | tr -d '"' | tr -d "'")
    if [ -n "$val" ]; then
      printf '%s\n' "$val"
      return
    fi
  fi
  branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo mainnet)
  case "$branch" in
    testnet) printf '%s\n' 'ghcr.io/echelonlabsresearch/zcrypt-abci:testnet' ;;
    *) printf '%s\n' 'ghcr.io/echelonlabsresearch/zcrypt-abci:mainnet' ;;
  esac
}

write_env() {
  dest=$1
  image=$2
  if [ -f .env ]; then
    grep -v '^ZCRYPT_ABCI_IMAGE=' .env > "$dest" || true
  else
    : > "$dest"
  fi
  printf 'ZCRYPT_ABCI_IMAGE=%s\n' "$image" >> "$dest"
}

command -v docker >/dev/null 2>&1 || die "install Docker first (docker.io or Docker Engine)"
compose_ok || install_compose
compose_ok || die "Docker Compose v2 is still not available. Install the docker-compose-plugin package."

IMAGE=$(image_ref)
envfile=$(mktemp)
write_env "$envfile" "$IMAGE"
echo "validator-up: image $IMAGE"
if dc --env-file "$envfile" -f docker-compose.validator.yml pull validator-abci; then
  dc --env-file "$envfile" -f docker-compose.validator.yml up -d
else
  echo "validator-up: $IMAGE is not pullable yet. Building zcrypt-abci:local from this checkout."
  echo "validator-up: the first build compiles Rust and takes a long time."
  write_env "$envfile" 'zcrypt-abci:local'
  dc --env-file "$envfile" \
    -f docker-compose.validator.yml \
    -f docker-compose.validator.build.yml \
    up -d --build
fi
rm -f "$envfile"

echo "validator-up: running. Follow sync with: docker logs -f zcrypt-validator-cometbft"
