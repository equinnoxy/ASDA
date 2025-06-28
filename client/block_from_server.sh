#!/bin/bash

# -------------------------------------
# Argumen: IP address yang ingin diblokir
# Digunakan oleh client.js untuk eksekusi lokal
# -------------------------------------

IP="$1"
BAN_DURATION="${2:-120}" # Default 120 minutes if not specified
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
  echo "$TIMESTAMP,,BLOCK,ERROR,Empty IP provided" >> "$BLOCK_LOG"
  exit 1
fi

if ! validate_ip "$IP"; then
  echo "[❌] Invalid IP format: $IP"
  echo "$TIMESTAMP,$IP,BLOCK,ERROR,Invalid IP format" >> "$BLOCK_LOG"
  exit 1
fi

# Check sudo access and fail2ban availability
if ! check_sudo; then
  echo "$TIMESTAMP,$IP,BLOCK,ERROR,No sudo access" >> "$BLOCK_LOG"
  exit 1
fi

if ! check_fail2ban; then
  echo "$TIMESTAMP,$IP,BLOCK,ERROR,fail2ban not available" >> "$BLOCK_LOG"
  exit 1
fi

# Blokir IP pakai Fail2Ban
echo "[🔒] Attempting to block IP $IP via Fail2Ban"
if ! BLOCK_OUTPUT=$(sudo fail2ban-client set sshd banip "$IP" 2>&1); then
  echo "[❌] Failed to block IP $IP: $BLOCK_OUTPUT"
  echo "$TIMESTAMP,$IP,BLOCK,ERROR,$BLOCK_OUTPUT" >> "$BLOCK_LOG"
  exit 1
fi

# Logging CSV
echo "$TIMESTAMP,$IP,BLOCK,SUCCESS," >> "$BLOCK_LOG"
echo "[✅] IP $IP diblokir via Fail2Ban" >> "$ACTIONS_LOG"
echo "[✅] Successfully blocked IP $IP via Fail2Ban"

# Jadwalkan unban via 'at'
# Check if 'at' command exists
if ! command -v at &> /dev/null; then
    echo "[⚠️] 'at' command not found. IP will remain blocked indefinitely."
    echo "$TIMESTAMP,$IP,SCHEDULE_UNBLOCK,ERROR,at command not available" >> "$BLOCK_LOG"
else
    UNBAN_CMD="/bin/bash $(pwd)/unblock_from_server.sh $IP"
    if ! echo "$UNBAN_CMD" | at now + $((BAN_DURATION / 60)) minutes 2>/dev/null; then
        echo "[⚠️] Failed to schedule unblock. IP will remain blocked indefinitely."
        echo "$TIMESTAMP,$IP,SCHEDULE_UNBLOCK,ERROR,Failed to schedule with at command" >> "$BLOCK_LOG"
    else
        echo "[✅] Scheduled unblock of $IP in $BAN_DURATION minutes"
        echo "$TIMESTAMP,$IP,SCHEDULE_UNBLOCK,SUCCESS,$BAN_DURATION minutes" >> "$BLOCK_LOG"
    fi
fi

exit 0
