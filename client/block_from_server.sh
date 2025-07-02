#!/bin/bash

# -------------------------------------
# Argumen: IP address yang ingin diblokir
# Digunakan oleh client.js untuk eksekusi lokal
# -------------------------------------

IP="$1"
SOURCE="${2:-direct}" # Source of the block (fail2ban, manual, etc.)
BAN_DURATION="${3:-120}" # Default 120 minutes if not specified

# Convert string to number for BAN_DURATION
if ! [[ "$BAN_DURATION" =~ ^[0-9]+$ ]]; then
    # If not a number, set to default
    BAN_DURATION=120
    echo "[⚠️] Invalid ban duration format. Using default of 120 minutes."
fi

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
  echo "$TIMESTAMP,,BLOCK,ERROR,Empty IP provided" >> "$BLOCK_LOG"
  exit 1
fi

if ! validate_ip "$IP"; then
  echo "[❌] Invalid IP format: $IP"
  echo "$TIMESTAMP,$IP,BLOCK,ERROR,Invalid IP format" >> "$BLOCK_LOG"
  exit 1
fi

# Block IP with iptables
echo "[🔒] Attempting to block IP $IP via iptables (source: $SOURCE, duration: $BAN_DURATION mins)"

# Debug: Check if sudo works at all
if ! sudo -n true 2>/dev/null; then
    echo "[❌] Sudo access is not available without a password. Please configure sudoers."
    echo "$TIMESTAMP,$IP,BLOCK,ERROR,No sudo access" >> "$BLOCK_LOG"
    exit 1
fi

# Debug: Check if iptables is available
if ! command -v iptables &> /dev/null; then
    echo "[❌] iptables command not found. Please install iptables."
    echo "$TIMESTAMP,$IP,BLOCK,ERROR,iptables command not found" >> "$BLOCK_LOG"
    exit 1
fi

# Debug: Check if we can use iptables with sudo without a password
if ! sudo -n iptables -L INPUT -n > /dev/null 2>&1; then
    echo "[❌] Cannot run iptables commands with sudo. Check sudoers configuration."
    echo "[ℹ️] Current sudo permissions:"
    sudo -l 2>&1 | tee -a "$ACTIONS_LOG"
    echo "$TIMESTAMP,$IP,BLOCK,ERROR,No sudo access for iptables commands" >> "$BLOCK_LOG"
    exit 1
fi

# First check if the IP is already blocked
if sudo iptables -C INPUT -s "$IP" -j DROP 2>/dev/null; then
    echo "[ℹ️] IP $IP is already blocked in iptables (DROP rule)"
else
    # Add the IP to the INPUT chain with DROP action
    echo "[🔄] Executing: sudo iptables -I INPUT -s $IP -j DROP"
    if ! sudo iptables -I INPUT -s "$IP" -j DROP; then
        echo "[❌] Failed to block IP $IP with iptables"
        echo "$TIMESTAMP,$IP,BLOCK,ERROR,Failed to add iptables rule" >> "$BLOCK_LOG"
        exit 1
    fi
    echo "[✅] Successfully added DROP rule for IP $IP"
fi

# Verify the rule was added
if ! sudo iptables -C INPUT -s "$IP" -j DROP 2>/dev/null; then
    echo "[⚠️] Rule verification failed. IP $IP may not be blocked."
    echo "$TIMESTAMP,$IP,BLOCK,WARNING,Rule verification failed" >> "$BLOCK_LOG"
else
    echo "[✅] Verified DROP rule exists for IP $IP"
fi

# Logging CSV
echo "$TIMESTAMP,$IP,BLOCK,SUCCESS," >> "$BLOCK_LOG"
echo "[✅] IP $IP diblokir via iptables" >> "$ACTIONS_LOG"
echo "[✅] Successfully blocked IP $IP via iptables"

# Jadwalkan unban via 'at'
# Check if 'at' command exists
if ! command -v at &> /dev/null; then
    echo "[⚠️] 'at' command not found. IP will remain blocked indefinitely."
    echo "$TIMESTAMP,$IP,SCHEDULE_UNBLOCK,ERROR,at command not available" >> "$BLOCK_LOG"
else
    # Schedule unblock
    UNBAN_CMD="$SCRIPT_DIR/unblock_from_server.sh $IP >/dev/null 2>&1"
    
    echo "[🔄] Scheduling unblock with command: $UNBAN_CMD"
    
    # Redirect stderr to stdout to capture all errors
    if ! echo "$UNBAN_CMD" | at now + $((BAN_DURATION / 60)) minutes 2>&1; then
        echo "[⚠️] Failed to schedule unblock. IP will remain blocked indefinitely."
        echo "$TIMESTAMP,$IP,SCHEDULE_UNBLOCK,ERROR,Failed to schedule with at command" >> "$BLOCK_LOG"
    else
        echo "[✅] Scheduled unblock of $IP in $BAN_DURATION minutes"
        echo "$TIMESTAMP,$IP,SCHEDULE_UNBLOCK,SUCCESS,$BAN_DURATION minutes" >> "$BLOCK_LOG"
    fi
fi

exit 0
