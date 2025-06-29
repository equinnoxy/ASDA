#!/bin/bash

# -------------------------------------
# Argumen: IP address yang ingin dilepas blokir
# Digunakan oleh client.js untuk eksekusi lokal
# -------------------------------------

IP="$1"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Get the script's absolute directory path
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
LOG_DIR="${SCRIPT_DIR}/logs"
ACTIONS_LOG="${LOG_DIR}/actions.log"
BLOCK_LOG="${LOG_DIR}/block_log.csv"

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

# Validate input
if [ -z "$IP" ]; then
  echo "[❌] IP kosong."
  echo "$TIMESTAMP,,UNBLOCK,ERROR,Empty IP provided" >> "$BLOCK_LOG"
  exit 1
fi

if ! validate_ip "$IP"; then
  echo "[❌] Invalid IP format: $IP"
  echo "$TIMESTAMP,$IP,UNBLOCK,ERROR,Invalid IP format" >> "$BLOCK_LOG"
  exit 1
fi

# Try to remove the DROP rule
UNBLOCKED=false

# Check and remove from INPUT chain
if sudo iptables -C INPUT -s "$IP" -j DROP 2>/dev/null; then
    if sudo iptables -D INPUT -s "$IP" -j DROP; then
        echo "[✅] Removed DROP rule for IP $IP from INPUT chain."
        UNBLOCKED=true
    fi
fi

# Check and remove from INPUT chain (REJECT rule)
if sudo iptables -C INPUT -s "$IP" -j REJECT 2>/dev/null; then
    if sudo iptables -D INPUT -s "$IP" -j REJECT; then
        echo "[✅] Removed REJECT rule for IP $IP from INPUT chain."
        UNBLOCKED=true
    fi
fi

if [ "$UNBLOCKED" = true ]; then
    echo "[✅] IP $IP successfully unblocked."
    echo "$TIMESTAMP,$IP,UNBLOCK,SUCCESS,iptables" >> "$BLOCK_LOG"
    echo "[✅] IP $IP di-unban via iptables" >> "$ACTIONS_LOG"
    exit 0
else
    echo "[⚠️] IP $IP was not found in iptables rules or could not be removed."
    echo "$TIMESTAMP,$IP,UNBLOCK,WARNING,IP not found in iptables" >> "$BLOCK_LOG"
    # Not a failure if IP wasn't blocked to begin with
    exit 0
fi
