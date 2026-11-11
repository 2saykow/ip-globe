# IP Globe

Globe 3D des connexions réseau de ton PC, en direct : chaque IP est placée à sa vraie position,
colorée selon son niveau de danger (reverse shell, IP malveillante connue, programme louche…),
avec possibilité de couper ou bloquer une connexion.

## Installation (Linux)

```bash
git clone https://github.com/2saykow/ip-globe.git && cd ip-globe
./install.sh
```

Il faut `python3`, `curl`, `ss` (paquet iproute2) et un navigateur avec WebGL.
Pour couper/bloquer : `pkexec` (polkit) et `nft` (nftables) ; un mot de passe administrateur est demandé à chaque action.

## Utilisation

Lance **IP Globe** depuis le menu des applications (ou `./ip-globe.sh`), la page s'ouvre sur http://127.0.0.1:8765.
Arrêter le serveur : `pkill -f "venv/bin/python server.py"`.

## Couleurs

| Couleur | Sens |
|---|---|
| Rouge | danger : reverse shell probable, IP malveillante connue, programme lancé depuis /tmp ou supprimé |
| Orange | suspect : port de pirate (4444, 1337…), shell/interpréteur connecté, programme invisible |
| Violet / Bleu / Vert | entrant / sortant / réseau local, rien de suspect |

## Vie privée

- Le serveur n'écoute que sur 127.0.0.1 et exige un jeton secret pour les actions.
- La géolocalisation est hors ligne (bases DB-IP Lite). Aucune IP n'est envoyée à un service externe.
- Les listes de menaces (abuse.ch Feodo, Spamhaus DROP) sont téléchargées entières une fois par jour.
- La page charge three.js, 3d-force-graph et la carte du monde depuis unpkg / jsDelivr.

## Limites

Ce n'est pas un antivirus : la détection repose sur des signes typiques. Sans droits root, les processus
des autres utilisateurs sont « invisibles ». Les blocages disparaissent au redémarrage.

Données de géolocalisation : IP Geolocation by DB-IP (https://db-ip.com), licence CC BY 4.0.
