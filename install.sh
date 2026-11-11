#!/usr/bin/env bash
# Installe IP Globe : environnement Python, bases de géolocalisation DB-IP Lite, entrée dans le menu.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
DIR=$PWD

for cmd in python3 ss curl gunzip xdg-open; do
  command -v "$cmd" >/dev/null || { echo "Il manque la commande : $cmd" >&2; exit 1; }
done

[ -d venv ] || python3 -m venv venv
venv/bin/pip install -q maxminddb

# Bases DB-IP Lite (gratuites, CC BY 4.0) : celle du mois, sinon celle du mois précédent.
fetch_db() {
  local kind=$1 out=$2
  [ -f "$out" ] && return
  for m in "$(date +%Y-%m)" "$(date -d '-1 month' +%Y-%m)"; do
    if curl -sfL "https://download.db-ip.com/free/dbip-$kind-lite-$m.mmdb.gz" -o "$out.gz"; then
      gunzip -f "$out.gz"; echo "Base $kind téléchargée ($m)"; return
    fi
  done
  echo "Téléchargement impossible : dbip-$kind-lite" >&2; exit 1
}
fetch_db city dbip-city-lite.mmdb
fetch_db asn dbip-asn-lite.mmdb

chmod +x ip-globe.sh
mkdir -p ~/.local/share/applications
cat > ~/.local/share/applications/ip-globe.desktop <<EOF
[Desktop Entry]
Type=Application
Name=IP Globe
Comment=Globe 3D des IP connectées à ce PC, en direct
Exec=$DIR/ip-globe.sh
Icon=applications-internet
Terminal=false
Categories=Network;
EOF
venv/bin/python server.py --selftest
echo "Installé. Lance « IP Globe » depuis le menu, ou : $DIR/ip-globe.sh"
