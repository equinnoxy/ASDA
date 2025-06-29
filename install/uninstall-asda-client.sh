#!/bin/bash

# ASDA Client Uninstaller Script
# This script completely removes all components of ASDA Client to allow for a fresh installation

# Function to print colorized output
print_status() {
    local color=$1
    local message=$2
    
    case "$color" in
        "green") echo -e "\e[32m$message\e[0m" ;;
        "red") echo -e "\e[31m$message\e[0m" ;;
        "yellow") echo -e "\e[33m$message\e[0m" ;;
        "blue") echo -e "\e[34m$message\e[0m" ;;
        *) echo "$message" ;;
    esac
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_status "red" "Please run as root (use sudo)"
    exit 1
fi

print_status "blue" "ASDA Client Uninstaller"
print_status "blue" "======================="
print_status "yellow" "This script will completely remove all ASDA Client components from your system."
print_status "yellow" "This includes services, files, configuration, and user permissions."
read -p "Are you sure you want to proceed? (y/N): " confirm

if [[ "$confirm" != [Yy]* ]]; then
    print_status "yellow" "Uninstallation cancelled."
    exit 0
fi

# 1. Stop and disable ASDA client service
print_status "blue" "Stopping and disabling ASDA Client service..."
systemctl stop asda-client 2>/dev/null
systemctl disable asda-client 2>/dev/null
print_status "green" "ASDA Client service stopped and disabled."

# 2. Remove the systemd service file
print_status "blue" "Removing systemd service file..."
rm -f /etc/systemd/system/asda-client.service
systemctl daemon-reload
print_status "green" "Systemd service file removed."

# 3. Kill any running processes
print_status "blue" "Killing any running ASDA Client processes..."
pkill -f "node.*client.js" 2>/dev/null
print_status "green" "All ASDA Client processes terminated."

# 4. Remove pending 'at' jobs for unblocking IPs
print_status "blue" "Removing scheduled at jobs..."
# List and remove all at jobs from asda user
if id -u asda &>/dev/null; then
    # Get all job numbers for asda user
    for job in $(atq | grep asda | awk '{print $1}'); do
        atrm $job 2>/dev/null
    done
fi
print_status "green" "Scheduled jobs removed."

# 5. Remove sudo permissions
print_status "blue" "Removing sudo permissions..."
rm -f /etc/sudoers.d/asda-security
rm -f /etc/sudoers.d/asda-fail2ban
print_status "green" "Sudo permissions removed."

# 6. Remove Fail2Ban integration
print_status "blue" "Checking for ASDA Fail2Ban configuration..."
if [ -f /etc/fail2ban/action.d/asda-notify.conf ]; then
    rm -f /etc/fail2ban/action.d/asda-notify.conf
    print_status "green" "Fail2Ban action configuration removed."
fi

if [ -f /etc/fail2ban/jail.d/sshd-asda.conf ]; then
    rm -f /etc/fail2ban/jail.d/sshd-asda.conf
    print_status "green" "Fail2Ban jail configuration removed."
fi

# 7. Restart Fail2Ban to apply changes
if systemctl is-active --quiet fail2ban; then
    print_status "blue" "Restarting Fail2Ban service..."
    systemctl restart fail2ban
    print_status "green" "Fail2Ban service restarted."
fi

# 8. Unblock any IPs that were blocked by ASDA
print_status "blue" "Checking for IPs blocked by ASDA..."
# Find any DROP rules that might have been added by ASDA
BLOCKED_IPS=$(sudo iptables -L INPUT -n | grep DROP | awk '{print $4}' | grep -v "0.0.0.0/0")

if [ -n "$BLOCKED_IPS" ]; then
    print_status "yellow" "Found potentially blocked IPs, attempting to unblock..."
    for ip in $BLOCKED_IPS; do
        sudo iptables -D INPUT -s $ip -j DROP 2>/dev/null
        print_status "green" "Unblocked IP: $ip"
    done
else
    print_status "green" "No blocked IPs found."
fi

# 9. Remove the ASDA client directory
print_status "blue" "Removing ASDA Client files..."
rm -rf /opt/asda/client
print_status "green" "ASDA Client files removed."

# 10. Ask if the user wants to remove the asda user
read -p "Do you want to remove the 'asda' user from the system? (y/N): " remove_user
if [[ "$remove_user" == [Yy]* ]]; then
    print_status "blue" "Removing asda user..."
    
    # Kill any processes owned by asda
    pkill -u asda 2>/dev/null
    
    # Remove user and home directory
    userdel -r asda 2>/dev/null
    
    # If home directory still exists, force remove it
    if [ -d /home/asda ]; then
        rm -rf /home/asda
    fi
    
    print_status "green" "User 'asda' removed."
else
    print_status "yellow" "Keeping the 'asda' user. You can remove it later with 'sudo userdel -r asda'."
fi

# 11. Remove /opt/asda directory if empty
if [ -d /opt/asda ] && [ -z "$(ls -A /opt/asda)" ]; then
    print_status "blue" "Removing empty /opt/asda directory..."
    rmdir /opt/asda
    print_status "green" "Directory removed."
fi

print_status "green" "✅ ASDA Client has been completely uninstalled from your system."
print_status "yellow" "You can now perform a fresh installation."
print_status "blue" "To reinstall, run the install.sh script from your ASDA distribution."

exit 0
