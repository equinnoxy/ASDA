#!/bin/bash

# -------------------------------------
# Argumen: IP address yang ingin dilepas blokir
# Digunakan oleh client.js untuk eksekusi lokal
# -------------------------------------

IP="$1"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

if [ -z "$IP" ]; then
  echo "[❌] IP kosong."
  exit 1
fi

# Unban IP
sudo fail2ban-client set sshd unbanip "$IP"

# Logging CSV
echo "$TIMESTAMP,$IP,UNBLOCK" >> ./logs/block_log.csv
echo "[✅] IP $IP di-unban otomatis via Fail2Ban" >> ./logs/actions.log
