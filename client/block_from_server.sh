#!/bin/bash

# -------------------------------------
# Dummy Script: block_from_server.sh
# -------------------------------------
# Argumen: IP address yang ingin diblokir
# Digunakan oleh client.js untuk eksekusi lokal
# Nanti akan dihubungkan ke fail2ban/iptables
# -------------------------------------

IP="$1"

if [ -z "$IP" ]; then
  echo "[❌] Tidak ada IP yang diberikan."
  exit 1
fi

echo "[✅] Simulasi pemblokiran IP: $IP" >> ./logs/actions.log
echo "[INFO] IP $IP berhasil diproses oleh block_from_server.sh"
