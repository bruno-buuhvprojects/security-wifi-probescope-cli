#!/usr/bin/env bash
# Instala as dependencias de sistema para compilar o addon nativo "cap"
# (binding do libpcap) usado na captura ao vivo. Deteta o gerenciador de
# pacotes e usa sudo so quando o usuario nao e root. Depois disto, o
# dispatcher roda 'npm rebuild cap'.
set -euo pipefail

echo "== Setup de captura ao vivo (Linux) =="

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    echo "Sem privilegio de root e sem sudo; rode este script como root." >&2
    exit 1
  fi
fi

if command -v apt-get >/dev/null 2>&1; then
  echo "-> apt detectado; instalando libpcap-dev + toolchain..."
  $SUDO apt-get update
  $SUDO apt-get install -y libpcap-dev build-essential python3
elif command -v dnf >/dev/null 2>&1; then
  echo "-> dnf detectado..."
  $SUDO dnf install -y libpcap-devel gcc gcc-c++ make python3
elif command -v yum >/dev/null 2>&1; then
  echo "-> yum detectado..."
  $SUDO yum install -y libpcap-devel gcc gcc-c++ make python3
elif command -v pacman >/dev/null 2>&1; then
  echo "-> pacman detectado..."
  $SUDO pacman -Sy --noconfirm libpcap base-devel python
elif command -v zypper >/dev/null 2>&1; then
  echo "-> zypper detectado..."
  $SUDO zypper install -y libpcap-devel gcc gcc-c++ make python3
elif command -v apk >/dev/null 2>&1; then
  echo "-> apk detectado..."
  $SUDO apk add libpcap-dev build-base python3
else
  echo "Nenhum gerenciador conhecido (apt/dnf/yum/pacman/zypper/apk)." >&2
  echo "Instale manualmente os headers do libpcap e um toolchain C/C++." >&2
  exit 1
fi

echo "== Dependencias de sistema prontas. =="
echo
echo "Dica: para capturar sem root, conceda as capabilities ao binario do node:"
echo "  sudo setcap cap_net_raw,cap_net_admin+eip \$(readlink -f \"\$(command -v node)\")"
