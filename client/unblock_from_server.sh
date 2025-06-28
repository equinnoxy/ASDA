#!/bin/bash

# -------------------------------------
# Argumen: IP address yang ingin dilepas blokir
# Digunakan oleh client.js untuk eksekusi lokal
# -------------------------------------

IP="$1"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
LOG_DIR="./logs"
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

# Validate sudo access
function check_sudo() {
    if ! sudo -n true 2>/dev/null; then
        echo "[❌] No sudo access available. Please configure passwordless sudo for fail2ban commands."
        return 1
    fi
    return 0
}

# Check if fail2ban is available
function check_fail2ban() {
    if ! command -v fail2ban-client &> /dev/null; then
        echo "[❌] fail2ban-client command not found. Please install fail2ban."
        return 1
    fi
    return 0
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

# Check sudo access and fail2ban availability
if ! check_sudo; then
  echo "$TIMESTAMP,$IP,UNBLOCK,ERROR,No sudo access" >> "$BLOCK_LOG"
  exit 1
fi

if ! check_fail2ban; then
  echo "$TIMESTAMP,$IP,UNBLOCK,ERROR,fail2ban not available" >> "$BLOCK_LOG"
  exit 1
fi

# Unban IP
echo "[🔓] Attempting to unblock IP $IP via Fail2Ban"
if ! UNBLOCK_OUTPUT=$(sudo fail2ban-client set sshd unbanip "$IP" 2>&1); then
  echo "[❌] Failed to unblock IP $IP: $UNBLOCK_OUTPUT"
  echo "$TIMESTAMP,$IP,UNBLOCK,ERROR,$UNBLOCK_OUTPUT" >> "$BLOCK_LOG"
  exit 1
fi

# Logging CSV
echo "$TIMESTAMP,$IP,UNBLOCK,SUCCESS," >> "$BLOCK_LOG"
echo "[✅] IP $IP di-unban via Fail2Ban" >> "$ACTIONS_LOG"
echo "[✅] Successfully unblocked IP $IP via Fail2Ban"

exit 0
