#!/bin/bash

# --------------------------------------------
# Script ini dipanggil otomatis oleh Fail2Ban
# saat sebuah IP diblokir oleh jail sshd
# --------------------------------------------
# Argumen 1: IP address penyerang
# --------------------------------------------

IP="$1"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
QUEUE_FILE=".ip_queue"
LOG_DIR="./logs"
ACTIONS_LOG="${LOG_DIR}/actions.log"

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Validate IP format
function validate_ip() {
    local ip=$1
    local stat=1
    
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

if [ -z "$IP" ]; then
  echo "[❌] Tidak ada IP yang diberikan ke trigger." | tee -a "$ACTIONS_LOG"
  exit 1
fi

# Validate IP
if ! validate_ip "$IP"; then
  echo "[❌] Invalid IP format received: $IP" | tee -a "$ACTIONS_LOG"
  exit 1
fi

# Check if IP is already in queue
if [ -f "$QUEUE_FILE" ] && grep -q "^$IP$" "$QUEUE_FILE"; then
  echo "[INFO] IP $IP already in queue, skipping" | tee -a "$ACTIONS_LOG"
  exit 0
fi

# Tambahkan ke file antrian
echo "$IP" >> "$QUEUE_FILE"
echo "[${TIMESTAMP}] [INFO] IP $IP dimasukkan ke antrean $QUEUE_FILE" | tee -a "$ACTIONS_LOG"

# Set proper permissions on queue file
chmod 644 "$QUEUE_FILE"

exit 0
