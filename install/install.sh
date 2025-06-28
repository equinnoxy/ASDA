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
        curl -fsSL https://deb.nodesource.com/setup_16.x | bash -
        apt-get install -y nodejs
    elif command -v dnf &> /dev/null; then
        # Fedora/RHEL 8+
        dnf module install -y nodejs:16
    elif command -v yum &> /dev/null; then
        # CentOS/RHEL 7
        curl -fsSL https://rpm.nodesource.com/setup_16.x | bash -
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

case $option in
    1)
        # Install ASDA Client
        print_status "blue" "Installing ASDA Client..."
        
        # Create installation directory
        mkdir -p /opt/asda/client/logs
        
        # Create user
        if ! id -u asda &> /dev/null; then
            useradd -r -s /bin/false asda
        fi
        
        # Copy files
        read -p "Enter path to ASDA client files: " client_path
        if [ ! -d "$client_path" ]; then
            print_status "red" "Directory not found: $client_path"
            exit 1
        fi
        
        cp -r "$client_path"/* /opt/asda/client/
        
        # Fix permissions
        chown -R asda:asda /opt/asda/client
        chmod +x /opt/asda/client/*.sh
        
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
        
        # Configure Fail2Ban integration
        cp /opt/asda/client/install/asda-notify.conf /etc/fail2ban/action.d/
        cp /opt/asda/client/install/sshd-asda.conf /etc/fail2ban/jail.d/
        
        # Install systemd service
        cp /opt/asda/client/install/asda-client.service /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable asda-client
        systemctl start asda-client
        
        # Restart Fail2Ban
        systemctl restart fail2ban
        
        print_status "green" "ASDA Client installation complete!"
        print_status "blue" "Service status: $(systemctl is-active asda-client)"
        ;;
        
    2)
        # Install ASDA Server
        print_status "blue" "Installing ASDA Server..."
        
        # Create installation directory
        mkdir -p /opt/asda/server/logs
        
        # Create user
        if ! id -u asda &> /dev/null; then
            useradd -r -s /bin/false asda
        fi
        
        # Copy files
        read -p "Enter path to ASDA server files: " server_path
        if [ ! -d "$server_path" ]; then
            print_status "red" "Directory not found: $server_path"
            exit 1
        fi
        
        cp -r "$server_path"/* /opt/asda/server/
        
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
        cp /opt/asda/server/install/asda-server.service /etc/systemd/system/
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
