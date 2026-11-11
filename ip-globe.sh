#!/usr/bin/env bash
# Démarre le serveur IP Globe (s'il ne tourne pas déjà) puis ouvre la page.
cd "$(dirname "$0")"
if ! curl -s -o /dev/null -H 'Host: 127.0.0.1:8765' http://127.0.0.1:8765/; then
  setsid ./venv/bin/python server.py >/dev/null 2>&1 &
  for _ in $(seq 20); do curl -s -o /dev/null http://127.0.0.1:8765/ && break; sleep 0.25; done
fi
xdg-open http://127.0.0.1:8765/
