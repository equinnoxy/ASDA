#!/bin/bash

# -------------------------------------
# Argumen: IP address yang ingin diblokir
# Digunakan oleh client.js untuk eksekusi lokal
# -------------------------------------

IP="$1"
BAN_DURATION=120
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

if [ -z "$IP" ]; then
  echo "[❌] IP kosong."
  exit 1
fi

# Blokir IP pakai Fail2Ban
sudo fail2ban-client set sshd banip "$IP"

# Logging CSV
echo "$TIMESTAMP,$IP,BLOCK" >> ./logs/block_log.csv
echo "[✅] IP $IP diblokir via Fail2Ban" >> ./logs/actions.log

# Jadwalkan unban via 'at'
UNBAN_CMD="bash $(pwd)/unblock_from_server.sh $IP"
echo "$UNBAN_CMD" | at now + $((BAN_DURATION / 60)) minutes
