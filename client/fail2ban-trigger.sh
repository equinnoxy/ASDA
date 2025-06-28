#!/bin/bash

# --------------------------------------------
# Script called automatically by Fail2Ban
# when an IP is blocked by the sshd jail
# --------------------------------------------
# Argument 1: Attacker's IP address
# --------------------------------------------

IP="$1"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
QUEUE_FILE=".ip_queue"
LOG_DIR="./logs"
ACTIONS_LOG="${LOG_DIR}/actions.log"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
BLOCK_SCRIPT="${SCRIPT_DIR}/block_from_server.sh"

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
  echo "[❌] No IP provided to trigger." | tee -a "$ACTIONS_LOG"
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

# Add to queue file
echo "$IP" >> "$QUEUE_FILE"
echo "[${TIMESTAMP}] [INFO] IP $IP added to queue $QUEUE_FILE" | tee -a "$ACTIONS_LOG"

# Set proper permissions on queue file
chmod 644 "$QUEUE_FILE"

# Call the blocking script directly
if [ -f "$BLOCK_SCRIPT" ]; then
  echo "[${TIMESTAMP}] [INFO] Executing blocking script for IP $IP" | tee -a "$ACTIONS_LOG"
  /bin/bash "$BLOCK_SCRIPT" "$IP" "fail2ban" || {
    echo "[${TIMESTAMP}] [ERROR] Failed to execute blocking script for IP $IP" | tee -a "$ACTIONS_LOG"
  }
else
  echo "[${TIMESTAMP}] [ERROR] Blocking script not found at $BLOCK_SCRIPT" | tee -a "$ACTIONS_LOG"
fi

exit 0