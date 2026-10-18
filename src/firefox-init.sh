#!/bin/sh
# Rulat la pornirea containerului firefox (montat in /etc/cont-init.d/),
# ca root, INAINTE sa porneasca firefox-ul.

# firefox sta la 198.7.0.2 pe net2 = exact unde se intampla arp spoofingul
# trebuie fortam default route prin containerul router (198.7.0.1) ca tot traficul
# lui sa treaca prin middle
# fara asta default gateway-ul ar fi bridge-ul docker (198.7.1.1) si ar
# ocoli middle deci imaginea nu s-ar mai inlocui
set -x # trace mode enabled pentru debugging 

# imaginea de baza alpine poate sa nu aiba comanda ip deci trebuie instalata
# pe ruta default initiala, deci apk merge pentru ca are internet:)
if ! command -v ip >/dev/null 2>&1; then
    apk add --no-cache iproute2 >/dev/null 2>&1 || true
fi

if command -v ip >/dev/null 2>&1; then # reconfigurarea rutei cand comanda ip exista
    ip route del default 2>/dev/null
    ip route add default via 198.7.0.1
else
    # fallback daca ip tot lipseste 
    route del default 2>/dev/null
    route add default gw 198.7.0.1
fi
