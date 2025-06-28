# 🛡️ Adaptive SSH Defense Agents (ASDA)

ASDA is a distributed system for detecting, blocking, and sharing information about SSH brute force attacks automatically between servers using Fail2Ban and WebSockets.

---

## 📦 Project Structure

```
server/ 
├── server.js              # WebSocket server, REST API and dashboard backend
├── .env                   # Environment configuration
├── package.json           # Dependencies
├── logs/                  # Server logs
│   ├── server_log.csv     # All forwarded IPs
│   └── received_ips.log   # All received IPs
└── public/                # Admin dashboard files
    ├── index.html         # Dashboard UI
    ├── login.html         # Authentication login page
    ├── style.css          # Dashboard styling
    └── script.js          # Dashboard functionality and API integration

client/ 
├── client.js              # WebSocket client
├── .env                   # Environment configuration
├── package.json           # Dependencies
├── block_from_server.sh   # Script to block IPs
├── unblock_from_server.sh # Script to unblock IPs
├── fail2ban-trigger.sh    # Called by Fail2Ban on ban
├── .ip_queue              # Queue file for IPs to send
└── logs/                  # Client logs
    ├── actions.log        # Human-readable log
    └── block_log.csv      # CSV log of all actions

install/
├── install.sh             # Installation script
├── asda-client.service    # Systemd service for client
├── asda-server.service    # Systemd service for server
├── asda-notify.conf       # Fail2Ban action config
└── sshd-asda.conf         # Fail2Ban jail config
```

---

## ⚙️ Technologies & Dependencies

- **Backend**:
  - Node.js (v16+)
  - Express.js (for REST API and admin dashboard)
  - WebSocket (`ws` package for real-time communication)
  - MySQL/MariaDB (for persistent storage)
  - bcrypt (for password hashing)
  - express-session & cookie-parser (for authentication)
  - axios (for webhook notifications)
  - uuid (for session management)
  - dotenv (for environment configuration)

- **Security**:
  - Fail2Ban (active on `sshd` jail)
  - atd (for scheduling automatic unbans)
  - bcrypt password hashing
  - Session-based authentication
  - Role-based access control

- **Frontend**:
  - Bootstrap 5 (UI framework)
  - Chart.js (for dashboard metrics)
  - Bootstrap Icons
  - Vanilla JavaScript

- **System Requirements**:
  - Ubuntu/Debian-based system (for installation script)
  - Systemd (for service management)

---

## 📜 How the System Works

1. **Detection**: Fail2Ban detects SSH brute force attempts
2. **Trigger**: `fail2ban-trigger.sh` is called → IP is added to `.ip_queue`
3. **Distribution**: `client.js` reads the queue → sends IP to WebSocket Server
4. **Database**: Server stores the IP in MySQL database
5. **Broadcast**: `server.js` distributes the IP to all other clients
6. **Block**: All clients call `block_from_server.sh` → Fail2Ban blocks the IP
7. **Automatic Unban**: `unblock_from_server.sh` is scheduled by `at` after the configured ban duration
8. **Metrics**: Clients send performance metrics to the server
9. **Dashboard**: Admin can view clients, blocked IPs, and metrics via web interface

---

## � Security Features

- **Connection Management**:
  - Automatic reconnection with exponential backoff
  - Heartbeat mechanism to detect stale connections
  - Handling for temporary network failures

- **Error Handling**:
  - Comprehensive error handling in shell scripts
  - Error reporting back to server when blocks fail
  - Validation before executing commands with sudo

- **System Management**:
  - Admin interface/dashboard for managing clients
  - Query system for current block status across network
  - Mechanism to manually remove IPs from blocklist
  - Centralized configuration management

- **Monitoring and Logging**:
  - Detailed logging with timestamps and status
  - Alerting system to dashboard and Discord webhook
  - Performance metrics tracking

---

## 📊 Dashboard Features

The admin dashboard provides the following features:

- **Overview**: Total clients, active clients, blocked IPs, total events
- **Client Management**: View client status, last seen time, version
- **IP Management**: View and manage blocked IPs (block/unblock)
- **Metrics**: View performance metrics from all clients
- **Manual Controls**: Manually block or unblock IPs across all clients
- **User Management**: Create, edit, and delete dashboard users with role-based access
- **Authentication**: Secure login with bcrypt-hashed passwords stored in MySQL

---

## 📡 WebSocket Message Format

All communication between clients and server uses a standardized JSON format for consistency, easy management, and secure parsing.

### Client to Server Messages:

- **Registration**:
```json
{
  "type": "REGISTER",
  "client_id": "server1",
  "token": "secret_token"
}
```
  - Sent once when client connects to server
  - Must include `client_id` and `token`

- **Heartbeat**:
```json
{
  "type": "HEARTBEAT",
  "client_id": "server1",
  "token": "secret_token"
}
```

- **Block IP**:
```json
{
  "type": "BLOCK_IP",
  "client_id": "server1",
  "token": "secret_token",
  "ip": "192.168.1.100",
  "source": "fail2ban",
  "timestamp": "2025-06-28T12:34:56.789Z"
}
```
  - Sent by the reporting client to the server
  - Server validates the request and distributes to all other clients
  - Receiving clients execute `block_from_server.sh <IP>`

- **Block Result**:
```json
{
  "type": "BLOCK_RESULT",
  "client_id": "server1",
  "token": "secret_token",
  "ip": "192.168.1.100",
  "success": true,
  "timestamp": "2025-06-28T12:34:58.123Z"
}
```

- **Metrics**:
```json
{
  "type": "METRICS",
  "client_id": "server1",
  "token": "secret_token",
  "metrics": {
    "lastMinuteBlockCount": 5,
    "lastHourBlockCount": 23,
    "uptime": 3600,
    "memoryUsage": {
      "heapUsed": 24000000
    },
    "timestamp": "2025-06-28T12:35:00.000Z"
  }
}
```

### Server to Client Messages:

- **Heartbeat Acknowledgment**:
```json
{
  "type": "HEARTBEAT_ACK",
  "timestamp": "2025-06-28T12:34:56.000Z"
}
```

- **Block IP**:
```json
{
  "type": "BLOCK_IP",
  "client_id": "server2",
  "token": "secret_token",
  "ip": "192.168.1.100",
  "timestamp": "2025-06-28T12:34:56.789Z"
}
```

- **Unblock IP**:
```json
{
  "type": "UNBLOCK_IP",
  "client_id": "admin",
  "token": "secret_token",
  "ip": "192.168.1.100",
  "timestamp": "2025-06-28T12:40:00.000Z"
}
```

---

## 🛠️ Installation

### Automated Installation

1. Run the installation script as root:
```bash
sudo ./install/install.sh
```

2. Follow the prompts to install either the client or server.

### Manual Installation

#### Server Setup:

1. Install dependencies:
```bash
# Install Node.js if not already installed
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install MySQL/MariaDB if using database
sudo apt install mariadb-server

# Setup database
sudo mysql -e "CREATE DATABASE asda;"
sudo mysql -e "CREATE USER 'asda'@'localhost' IDENTIFIED BY 'password';"
sudo mysql -e "GRANT ALL PRIVILEGES ON asda.* TO 'asda'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

# Install server dependencies
cd server
npm install
```

2. Configure environment variables:
```bash
# Create .env file
cat > .env << EOF
PORT=3000
WEB_PORT=8080
SECRET_TOKEN=your_secret_token
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/your_webhook_url
DB_HOST=localhost
DB_USER=asda
DB_PASSWORD=password
DB_NAME=asda
DEFAULT_ADMIN_PASSWORD=admin123
SESSION_SECRET=your_session_secret
EOF
```

3. Start the server:
```bash
node server.js
```

#### Client Setup:

1. Install dependencies:
```bash
# Install required packages
sudo apt update
sudo apt install -y fail2ban at

# Install client dependencies
cd client
npm install
```

2. Configure environment variables:
```bash
# Create .env file
cat > .env << EOF
SERVER_IP=your_server_ip
SERVER_PORT=3000
CLIENT_ID=unique_client_id
SECRET_TOKEN=your_secret_token
EOF
```

3. Set up Fail2Ban integration:
```bash
# Copy action config to tell Fail2Ban to notify ASDA when IPs are banned
sudo cp install/asda-notify.conf /etc/fail2ban/action.d/

# Copy jail config to customize the SSH jail and add ASDA notification
sudo cp install/sshd-asda.conf /etc/fail2ban/jail.d/

# Check if the configuration is valid
sudo fail2ban-client -d

# Restart Fail2Ban to apply changes
sudo systemctl restart fail2ban

# Verify that the sshd jail is active and includes the ASDA action
sudo fail2ban-client status sshd
```

4. Make scripts executable:
```bash
chmod +x *.sh
```

5. Start the client:
```bash
node client.js
```

### Systemd Service Setup

1. Install systemd service files:
```bash
# For server
sudo cp install/asda-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now asda-server

# For client
sudo cp install/asda-client.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now asda-client
```

---

## � Monitoring & Maintenance

### Checking Logs

- **Server Logs**:
```bash
tail -f /opt/asda/server/logs/server_log.csv
```

- **Client Logs**:
```bash
tail -f /opt/asda/client/logs/actions.log
```

### Service Management

- **Check Status**:
```bash
sudo systemctl status asda-server
sudo systemctl status asda-client
```

- **Restart Services**:
```bash
sudo systemctl restart asda-server
sudo systemctl restart asda-client
```

### Database Maintenance

- **Backup Database**:
```bash
mysqldump -u asda -p asda > asda_backup.sql
```

- **Restore Database**:
```bash
mysql -u asda -p asda < asda_backup.sql
```

---

## 📋 Troubleshooting

- **Client can't connect to server**:
  - Verify network connectivity
  - Check firewall settings
  - Ensure the server is running
  - Verify secret token matches

- **Fail2Ban not triggering ASDA**:
  - Check Fail2Ban configuration: `sudo fail2ban-client status sshd`
  - Verify script permissions: `sudo chmod +x /opt/asda/client/*.sh`
  - Check if action is properly registered: `grep -r "asda-notify" /etc/fail2ban/`
  - Verify the trigger script works: `sudo /opt/asda/client/fail2ban-trigger.sh 192.168.1.100`
  - Examine logs: `sudo tail -f /var/log/fail2ban.log` and `tail -f /opt/asda/client/logs/actions.log`
  - Check if Fail2Ban service is running: `sudo systemctl status fail2ban`

- **Block/Unblock not working**:
  - Check sudo permissions
  - Verify Fail2Ban is running
  - Inspect client logs for errors

- **Authentication problems**:
  - Check that the database is properly configured
  - Verify that user tables are created correctly
  - Try resetting the admin password

---

## 🚀 Future Enhancements

- HTTPS/WSS support for secure communication
- JWT-based authentication
- Multi-service protection (not just SSH)
- Geolocation and threat intelligence integration
- Honeypot integration for proactive blocking
- Machine learning for attack pattern recognition

## � Authentication System

The ASDA system employs a comprehensive authentication system for both client-server communication and the admin dashboard.

### Client-Server Authentication

- All WebSocket messages must include a **secret token** (`token`) configured in `.env`
- The server validates this token before processing any message
- Messages without a valid token are **automatically ignored**

Example `.env` in Server:
```env
PORT=3000
SECRET_TOKEN=ASDA_SECRET_2025
```

Example `.env` in Client:
```env
SERVER_IP=127.0.0.1
SERVER_PORT=3000
CLIENT_ID=client-01
SECRET_TOKEN=ASDA_SECRET_2025
```

Messages are only processed if:
- JSON format is valid
- Required fields (`type`, `client_id`, and `token`) are present
- IP address is valid (for `BLOCK_IP` messages)
- Token matches the server's token (`process.env.SECRET_TOKEN`)

### Admin Dashboard Authentication

The admin dashboard uses a secure authentication system:

- **Backend**:
  - MySQL database storage for user accounts
  - bcrypt password hashing
  - Session-based authentication
  - Role-based access control (admin/user)

- **Frontend**:
  - Login page with secure form submission
  - Session validation
  - Automatic redirection to login when unauthenticated
  - Role-based UI elements

Default admin credentials are created during the first run (configurable in `.env`):
```
Username: admin
Password: admin123 (change this immediately after installation)
```

---

## 🚀 Current Status

- Production-ready with full security features
- Regular maintenance and security updates

---

This project was created as part of a final thesis research project.

## 🔗 Detailed Fail2Ban Integration

The integration between ASDA and Fail2Ban works through a custom action that notifies the ASDA client whenever Fail2Ban bans an IP address. Here's a detailed explanation of how to set it up and how it works:

### 1. Understanding the Components

**Fail2Ban Components:**
- **Filter**: Monitors log files and detects authentication failures (default `sshd` filter monitors SSH login attempts)
- **Jail**: Defines what action to take when failures are detected (e.g., ban the IP with iptables)
- **Action**: Defines what commands to execute when banning/unbanning IPs

**ASDA Components:**
- **fail2ban-trigger.sh**: Called by Fail2Ban when an IP is banned, adds IP to the queue
- **.ip_queue**: Queue file that stores IPs to be sent to the ASDA server
- **client.js**: Reads the queue and sends IPs to the ASDA server
- **asda-notify.conf**: Custom Fail2Ban action that calls the trigger script
- **sshd-asda.conf**: Custom Fail2Ban jail configuration for SSH that includes the ASDA action

### 2. Detailed Installation Steps

#### 2.1 Install the ASDA Action Configuration

```bash
# Copy the ASDA action config to Fail2Ban's action directory
sudo cp install/asda-notify.conf /etc/fail2ban/action.d/
```

The `asda-notify.conf` file defines an action that calls the ASDA trigger script when an IP is banned:

```properties
[Definition]
actionstart = 
actionstop = 
actioncheck = 
actionban = /opt/asda/client/fail2ban-trigger.sh <ip>
actionunban = 

[Init]
```

#### 2.2 Install the ASDA Jail Configuration

```bash
# Copy the ASDA jail config to Fail2Ban's jail directory
sudo cp install/sshd-asda.conf /etc/fail2ban/jail.d/
```

The `sshd-asda.conf` file modifies the SSH jail to include the ASDA action:

```properties
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5         # Number of failures before ban
findtime = 300       # Timeframe for failures (seconds)
bantime = 3600       # Ban duration (seconds)
banaction = iptables-multiport
action = %(action_)s # Default actions (ban with iptables)
         asda-notify # Our custom ASDA notification action
```

#### 2.3 Customize the Configuration (Optional)

You can adjust the Fail2Ban settings to match your security requirements:

```bash
# Create a custom jail configuration
sudo nano /etc/fail2ban/jail.local
```

Add or modify these settings:

```properties
[sshd]
# Increase sensitivity - ban after 3 failures within 5 minutes
maxretry = 3
findtime = 300

# Increase ban time to 24 hours
bantime = 86400

# Use both IPv4 and IPv6
banaction = iptables-multiport[name=ssh, port=ssh, protocol=tcp]
            iptables-multiport[name=ssh-ipv6, port=ssh, protocol=tcp]
            asda-notify
```

#### 2.4 Verify Fail2Ban Configuration

```bash
# Check if the configuration is valid
sudo fail2ban-client -d

# Check if the sshd jail is active
sudo fail2ban-client status sshd
```

#### 2.5 Restart Fail2Ban

```bash
sudo systemctl restart fail2ban
```

### 3. How It Works

1. **Detection**: Fail2Ban monitors `/var/log/auth.log` for failed SSH login attempts
2. **Threshold**: When an IP exceeds the threshold (default: 5 failed attempts within 5 minutes)
3. **Banning**: Fail2Ban executes two actions:
   - Uses iptables to block the IP address
   - Calls the ASDA action (`asda-notify`)
4. **ASDA Notification**: The `asda-notify` action calls `/opt/asda/client/fail2ban-trigger.sh <ip>`
5. **Queuing**: The `fail2ban-trigger.sh` script:
   - Validates the IP address format
   - Checks if the IP is already in the queue
   - Adds the IP to the `.ip_queue` file
6. **Distribution**: The ASDA client (`client.js`):
   - Periodically checks the `.ip_queue` file
   - Sends any new IPs to the ASDA server
   - The server distributes the IP to all other clients
7. **Network-wide Protection**: All other ASDA clients:
   - Receive the IP from the server
   - Execute `block_from_server.sh <ip>` to block the IP

### 4. Testing the Integration

You can test if the integration is working correctly by:

```bash
# Manually trigger the ASDA notification for a test IP
sudo /opt/asda/client/fail2ban-trigger.sh 192.168.1.100

# Check if the IP was added to the queue
cat /opt/asda/client/.ip_queue

# Check the ASDA client logs
tail -f /opt/asda/client/logs/actions.log

# Check if Fail2Ban received and processed SSH failures
sudo tail -f /var/log/fail2ban.log
```

### 5. Troubleshooting

If the integration is not working:

1. **Check Permissions**:
```bash
# Make sure scripts are executable
sudo chmod +x /opt/asda/client/*.sh

# Check if the ASDA user has permission to write to the queue file
sudo chown -R asda_user:asda_group /opt/asda/client/.ip_queue
sudo chmod 644 /opt/asda/client/.ip_queue
```

2. **Check Fail2Ban Configuration**:
```bash
# Verify that the ASDA action is properly included
sudo grep -r "asda-notify" /etc/fail2ban/

# Check if the sshd jail is enabled
sudo fail2ban-client status | grep sshd
```

3. **Test the Trigger Script Manually**:
```bash
# Run the script with debug output
sudo bash -x /opt/asda/client/fail2ban-trigger.sh 192.168.1.100
```

4. **Check Logs**:
```bash
# Check ASDA logs
tail -f /opt/asda/client/logs/actions.log

# Check Fail2Ban logs
sudo tail -f /var/log/fail2ban.log
```

