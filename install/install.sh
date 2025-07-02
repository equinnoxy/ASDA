#!/bin/bash

# ASDA Installation Script
# This script installs and configures the ASDA client or server

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

# Check NodeJS installation
if ! command -v node &> /dev/null || ! command -v npm &> /dev/null; then
    print_status "yellow" "NodeJS and NPM are required but not found. Installing..."
    
    # Install NodeJS and NPM
    if command -v apt-get &> /dev/null; then
        # Debian/Ubuntu
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt-get install -y nodejs
    elif command -v dnf &> /dev/null; then
        # Fedora/RHEL 8+
        dnf module install -y nodejs:16
    elif command -v yum &> /dev/null; then
        # CentOS/RHEL 7
        curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -
        yum install -y nodejs
    else
        print_status "red" "Unsupported package manager. Please install NodeJS manually."
        exit 1
    fi
    
    print_status "green" "NodeJS and NPM installed successfully"
fi

# Display menu
echo "ASDA Installation"
echo "================="
echo "1) Install ASDA Client"
echo "2) Install ASDA Server"
echo "3) Exit"
read -p "Choose an option (1-3): " option

# Ask for installation path upfront
if [ "$option" == "1" ] || [ "$option" == "2" ]; then
    component_type=$([ "$option" == "1" ] && echo "client" || echo "server")
    read -p "Enter path to ASDA ${component_type} files: " install_path
    
    if [ ! -d "$install_path" ]; then
        print_status "red" "Directory not found: $install_path"
        exit 1
    fi
fi

case $option in
    1)
        # Install ASDA Client
        print_status "blue" "Installing ASDA Client..."
        
        # Create installation directory
        mkdir -p /opt/asda/client/logs
        
        # Create user
        if ! id -u asda &> /dev/null; then
            # Create user with proper home directory and shell
            useradd -m -d /home/asda -s /bin/bash asda
            print_status "green" "Created asda user with home directory"
        else
            # Ensure home directory exists
            if [ ! -d "/home/asda" ]; then
                mkdir -p /home/asda
                chown asda:asda /home/asda
                print_status "green" "Created home directory for existing asda user"
            fi
        fi
        
        # Copy files (using the path collected earlier)
        cp -r "$install_path"/* /opt/asda/client/
        
        # Fix permissions
        chown -R asda:asda /opt/asda/client
        chmod +x /opt/asda/client/*.sh
        
        # Ensure scripts are directly executable without sudo
        print_status "blue" "Setting script permissions for direct execution..."
        find /opt/asda/client -name "*.sh" -exec chmod 755 {} \;
        
        # Install dependencies
        cd /opt/asda/client
        npm install
        
        # Configure .env file
        if [ ! -f /opt/asda/client/.env ]; then
            print_status "blue" "Configuring client settings..."
            read -p "Enter ASDA server IP: " server_ip
            read -p "Enter ASDA server port [3000]: " server_port
            server_port=${server_port:-3000}
            read -p "Enter client ID (unique identifier): " client_id
            read -p "Enter secret token: " secret_token
            
            echo "SERVER_IP=$server_ip" > /opt/asda/client/.env
            echo "SERVER_PORT=$server_port" >> /opt/asda/client/.env
            echo "CLIENT_ID=$client_id" >> /opt/asda/client/.env
            echo "SECRET_TOKEN=$secret_token" >> /opt/asda/client/.env
        fi
        
        # Install Fail2Ban if not present
        if ! command -v fail2ban-client &> /dev/null; then
            print_status "yellow" "Fail2Ban not found. Installing..."
            
            if command -v apt-get &> /dev/null; then
                apt-get install -y fail2ban
            elif command -v dnf &> /dev/null; then
                dnf install -y fail2ban
            elif command -v yum &> /dev/null; then
                yum install -y fail2ban
            else
                print_status "red" "Please install Fail2Ban manually"
            fi
        fi
        
        # Configure sudo access for fail2ban and iptables
        print_status "blue" "Configuring sudo access for fail2ban and iptables commands..."
        
        # Find the actual paths to the commands
        FAIL2BAN_PATH=$(which fail2ban-client 2>/dev/null || echo "/usr/bin/fail2ban-client")
        IPTABLES_PATH=$(which iptables 2>/dev/null || echo "/usr/sbin/iptables")
        
        # Create a more permissive sudoers file that allows full iptables command execution
        echo "# Allow asda user to run fail2ban and iptables commands without a password
asda ALL=(ALL) NOPASSWD: $FAIL2BAN_PATH
asda ALL=(ALL) NOPASSWD: $IPTABLES_PATH *" > /etc/sudoers.d/asda-security
        chmod 440 /etc/sudoers.d/asda-security
        
        print_status "blue" "Created sudoers file with the following content:"
        cat /etc/sudoers.d/asda-security
        
        # Verify the sudoers syntax
        if visudo -c -f /etc/sudoers.d/asda-security &>/dev/null; then
            print_status "green" "Sudo access configured successfully."
        else
            print_status "red" "Error in sudoers configuration. Please check manually."
            cat /etc/sudoers.d/asda-security
            rm -f /etc/sudoers.d/asda-security
        fi
        
        # Test sudo access directly to catch issues early
        print_status "blue" "Testing sudo access for asda user..."
        if su - asda -c "sudo -l" | grep -q "$IPTABLES_PATH"; then
            print_status "green" "Sudo access for iptables is correctly configured."
        else
            print_status "red" "Sudo access for iptables may not be working correctly. Please check manually."
            print_status "yellow" "Command output: $(su - asda -c "sudo -l")"
        fi
        
        # Configure Fail2Ban integration
        print_status "blue" "Configuring Fail2Ban integration..."

        # Ask for the installation path with default value
        read -p "Enter path to ASDA Fail2Ban configuration files [/root/ASDA/install/]: " fail2ban_path
        fail2ban_path=${fail2ban_path:-"/root/ASDA/install/"}

        # Make sure the path ends with a slash
        [[ "${fail2ban_path}" != */ ]] && fail2ban_path="${fail2ban_path}/"

        # Check if files exist in the specified path
        if [ -f "${fail2ban_path}asda-notify.conf" ] && [ -f "${fail2ban_path}sshd-asda.conf" ]; then
            # Copy Fail2Ban configuration files
            cp "${fail2ban_path}asda-notify.conf" /etc/fail2ban/action.d/
            cp "${fail2ban_path}sshd-asda.conf" /etc/fail2ban/jail.d/
            print_status "green" "Fail2Ban configuration files installed successfully."
        else
            print_status "red" "Could not find Fail2Ban configuration files in ${fail2ban_path}"
            print_status "red" "Make sure asda-notify.conf and sshd-asda.conf exist in the specified directory."
            print_status "red" "Fail2Ban integration will not work properly."
        fi

        # Install systemd service
        print_status "blue" "Installing systemd service..."

        # Ask for the installation path with default value
        read -p "Enter path to ASDA service files [/root/ASDA/install/]: " service_path
        service_path=${service_path:-"/root/ASDA/install/"}

        # Make sure the path ends with a slash
        [[ "${service_path}" != */ ]] && service_path="${service_path}/"

        # Check if service file exists in the specified path
        if [ -f "${service_path}asda-client.service" ]; then
            # Copy service file
            cp "${service_path}asda-client.service" /etc/systemd/system/
            print_status "green" "Service file installed successfully."
        else
            print_status "red" "Could not find asda-client.service in ${service_path}"
            print_status "red" "Service will not be installed properly."
            exit 1
        fi
        systemctl daemon-reload
        systemctl enable asda-client
        systemctl start asda-client
        
        # Restart Fail2Ban
        systemctl restart fail2ban
        
        print_status "green" "ASDA Client installation complete!"
        print_status "blue" "Service status: $(systemctl is-active asda-client)"
        
        # Print testing instructions
        print_status "yellow" "Testing Instructions:"
        print_status "yellow" "1. Switch to the asda user: su - asda"
        print_status "yellow" "2. Test blocking an IP: /opt/asda/client/block_from_server.sh 1.2.3.4"
        print_status "yellow" "3. Verify the block: sudo iptables -L INPUT -n | grep 1.2.3.4"
        print_status "yellow" "4. Test unblocking: /opt/asda/client/unblock_from_server.sh 1.2.3.4"
        print_status "yellow" "5. Verify it was removed: sudo iptables -L INPUT -n | grep 1.2.3.4"
        ;;
        
    2)
        # Install ASDA Server
        print_status "blue" "Installing ASDA Server..."
        
        # Create installation directory
        mkdir -p /opt/asda/server/logs
        
        # Create user
        if ! id -u asda &> /dev/null; then
            # Create user with proper home directory and shell
            useradd -m -d /home/asda -s /bin/bash asda
            print_status "green" "Created asda user with home directory"
        else
            # Ensure home directory exists
            if [ ! -d "/home/asda" ]; then
                mkdir -p /home/asda
                chown asda:asda /home/asda
                print_status "green" "Created home directory for existing asda user"
            fi
        fi
        
        # Copy files (using the path collected earlier)
        cp -r "$install_path"/* /opt/asda/server/
        
        # Fix permissions
        chown -R asda:asda /opt/asda/server
        
        # Install dependencies
        cd /opt/asda/server
        npm install
        
        # Configure MySQL
        read -p "Do you want to configure MySQL database? (y/n): " setup_db
        if [[ "$setup_db" =~ ^[Yy]$ ]]; then
            print_status "blue" "Setting up MySQL database..."
            
            read -p "MySQL host [localhost]: " db_host
            db_host=${db_host:-localhost}
            read -p "MySQL username [root]: " db_user
            db_user=${db_user:-root}
            read -p "MySQL password: " db_password
            read -p "Database name [asda]: " db_name
            db_name=${db_name:-asda}
            
            # Create database if it doesn't exist
            echo "CREATE DATABASE IF NOT EXISTS $db_name;" | mysql -u "$db_user" -p"$db_password" || {
                print_status "red" "Failed to create database. Please create it manually."
            }
        fi
        
        # Configure .env file
        if [ ! -f /opt/asda/server/.env ]; then
            print_status "blue" "Configuring server settings..."
            read -p "Enter server port [3000]: " server_port
            server_port=${server_port:-3000}
            read -p "Enter web dashboard port [8080]: " web_port
            web_port=${web_port:-8080}
            read -p "Enter secret token: " secret_token
            read -p "Enter Discord webhook URL (optional): " discord_webhook
            
            echo "PORT=$server_port" > /opt/asda/server/.env
            echo "WEB_PORT=$web_port" >> /opt/asda/server/.env
            echo "SECRET_TOKEN=$secret_token" >> /opt/asda/server/.env
            
            if [ -n "$discord_webhook" ]; then
                echo "DISCORD_WEBHOOK_URL=$discord_webhook" >> /opt/asda/server/.env
            fi
            
            if [[ "$setup_db" =~ ^[Yy]$ ]]; then
                echo "DB_HOST=$db_host" >> /opt/asda/server/.env
                echo "DB_USER=$db_user" >> /opt/asda/server/.env
                echo "DB_PASSWORD=$db_password" >> /opt/asda/server/.env
                echo "DB_NAME=$db_name" >> /opt/asda/server/.env
            fi
        fi
        
        # Install systemd service
        print_status "blue" "Installing systemd service..."

        # Ask for the installation path with default value
        read -p "Enter path to ASDA service files [/root/ASDA/install/]: " service_path
        service_path=${service_path:-"/root/ASDA/install/"}

        # Make sure the path ends with a slash
        [[ "${service_path}" != */ ]] && service_path="${service_path}/"

        # Check if service file exists in the specified path
        if [ -f "${service_path}asda-server.service" ]; then
            # Copy service file
            cp "${service_path}asda-server.service" /etc/systemd/system/
            print_status "green" "Service file installed successfully."
        else
            print_status "red" "Could not find asda-server.service in ${service_path}"
            print_status "red" "Service will not be installed properly."
            exit 1
        fi
        systemctl daemon-reload
        systemctl enable asda-server
        systemctl start asda-server
        
        # Configure firewall if available
        if command -v ufw &> /dev/null; then
            print_status "blue" "Configuring firewall..."
            ufw allow "$server_port"/tcp
            ufw allow "$web_port"/tcp
        elif command -v firewall-cmd &> /dev/null; then
            print_status "blue" "Configuring firewall..."
            firewall-cmd --permanent --add-port="$server_port"/tcp
            firewall-cmd --permanent --add-port="$web_port"/tcp
            firewall-cmd --reload
        fi
        
        print_status "green" "ASDA Server installation complete!"
        print_status "blue" "Service status: $(systemctl is-active asda-server)"
        print_status "blue" "Dashboard available at: http://$(hostname -I | awk '{print $1}'):$web_port"
        ;;
        
    3)
        print_status "yellow" "Installation cancelled"
        exit 0
        ;;
        
    *)
        print_status "red" "Invalid option"
        exit 1
        ;;
esac
