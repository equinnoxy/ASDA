require('dotenv').config();
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const express = require('express');
const http = require('http');
const mysql = require('mysql2/promise');
const axios = require('axios');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');

// Load configuration
const port = process.env.PORT || 3000;
const webPort = process.env.WEB_PORT || 8080;
const logPath = path.join(__dirname, 'logs', 'server_log.csv');
const receivedIpsLogPath = path.join(__dirname, 'logs', 'received_ips.log');
const discordWebhookUrl = process.env.DISCORD_WEBHOOK_URL || '';

// Request tracking for response time measurements
const pendingBlockRequests = new Map();
const REQUEST_TIMEOUT = 30000; // 30 seconds timeout

// Function to clean up pending requests that timeout
function cleanupPendingRequest(requestId) {
    const request = pendingBlockRequests.get(requestId);
    if (!request) return;
    
    // Record timeout events for any pending clients
    if (request.pendingClients.size > 0) {
        for (const [clientId, sentTime] of request.pendingClients.entries()) {
            // Calculate response time based on how long we waited
            const responseTime = Date.now() - sentTime;
            
            // Record a failed event with the timeout error
            recordBlockEvent(
                request.ip,
                clientId,
                request.action,
                false,
                'Response timed out',
                responseTime  // Use the actual timeout duration instead of null
            );
            console.log(`⏱️ ${request.action.toUpperCase()} request to ${clientId} for IP ${request.ip} timed out after ${responseTime}ms`);
        }
    }
    
    // Remove the request from tracking
    pendingBlockRequests.delete(requestId);
}

// Ensure logs directory exists
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

// Initialize database connection
let dbPool;
async function initDatabase() {
    try {
        dbPool = await mysql.createPool({
            host: process.env.DB_HOST || 'localhost',
            user: process.env.DB_USER || 'root',
            password: process.env.DB_PASSWORD || '',
            database: process.env.DB_NAME || 'asda',
            waitForConnections: true,
            connectionLimit: 10,
            queueLimit: 0
        });
        
        // Create tables if they don't exist
        await dbPool.query(`
            CREATE TABLE IF NOT EXISTS clients (
                id VARCHAR(255) PRIMARY KEY,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status ENUM('online', 'offline') DEFAULT 'offline',
                ip VARCHAR(255),
                first_connected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                version VARCHAR(50)
            )
        `);
        
        await dbPool.query(`
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip VARCHAR(45) PRIMARY KEY,
                first_blocked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_blocked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source VARCHAR(255),
                block_count INT DEFAULT 1,
                status ENUM('active', 'inactive') DEFAULT 'active'
            )
        `);
        
        await dbPool.query(`
            CREATE TABLE IF NOT EXISTS block_events (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip VARCHAR(45),
                client_id VARCHAR(255),
                action ENUM('block', 'unblock'),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN DEFAULT TRUE,
                error_message TEXT,
                response_time_ms INT
            )
        `);
        
        await dbPool.query(`
            CREATE TABLE IF NOT EXISTS metrics (
                client_id VARCHAR(255) PRIMARY KEY,
                first_reported TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_reported TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                blocks_last_minute INT DEFAULT 0,
                blocks_per_minute FLOAT DEFAULT 0,
                total_blocks INT DEFAULT 0,
                uptime_seconds FLOAT,
                memory_usage_mb FLOAT
            )
        `);

        // User authentication tables
        await dbPool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE,
                role ENUM('admin', 'user') DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL
            )
        `);

        await dbPool.query(`
            CREATE TABLE IF NOT EXISTS sessions (
                session_id VARCHAR(255) PRIMARY KEY,
                user_id INT NOT NULL,
                ip_address VARCHAR(45),
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        // Check if default admin user exists, create if not
        const [users] = await dbPool.query("SELECT * FROM users WHERE username = 'admin'");
        if (users.length === 0) {
            const defaultPassword = process.env.DEFAULT_ADMIN_PASSWORD || 'admin123';
            const hashedPassword = await bcrypt.hash(defaultPassword, 10);
            await dbPool.query(
                "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, 'admin')",
                ['admin', hashedPassword, 'admin@asda.local']
            );
            console.log('✅ Default admin user created');
        }
        
        console.log('✅ Database connection established and tables initialized');
    } catch (err) {
        console.error('❌ Database initialization failed:', err);
        console.log('⚠️ Running in memory-only mode');
    }
}

// Initialize Express app for dashboard
const app = express();
const server = http.createServer(app);

// Trust proxy headers if in production - necessary for secure cookies behind a proxy
if (process.env.NODE_ENV === 'production') {
    app.set('trust proxy', 1); // trust first proxy
}

if (process.env.BEHIND_CLOUDFLARE === 'true') {
    // Cloudflare sends client IP in CF-Connecting-IP
    app.set('trust proxy', true);
    
    // Log proxy detection
    console.log('✅ Cloudflare proxy detection enabled');
}

// Express middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(cookieParser());

// Session middleware
const sessionOptions = {
    secret: process.env.SESSION_SECRET || 'asda-session-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        // For Cloudflare proxy, check for X-Forwarded-Proto header
        secure: process.env.BEHIND_CLOUDFLARE === 'true' ? true : 
               (process.env.NODE_ENV === 'production' && process.env.DISABLE_SECURE_COOKIE !== 'true'),
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'lax'
    }
};

// Only configure MySQL session store if we have a DB connection
if (dbPool) {
    try {
        // Use existing connection options from the pool for consistency
        const dbConfig = {
            host: process.env.DB_HOST || 'localhost',
            port: 3306,
            user: process.env.DB_USER || 'root',
            password: process.env.DB_PASSWORD || '',
            database: process.env.DB_NAME || 'asda'
        };
        
        const sessionDBOptions = {
            ...dbConfig,
            // The sessions table is created by MySQL itself
            createDatabaseTable: true,
            schema: {
                tableName: 'sessions_store',
                columnNames: {
                    session_id: 'session_id',
                    expires: 'expires',
                    data: 'data'
                }
            },
            clearExpired: true,
            checkExpirationInterval: 900000, // How frequently expired sessions will be cleared (in ms) - 15 minutes
        };
        
        // Create MySQL session store
        const sessionStore = new MySQLStore(sessionDBOptions);
        sessionOptions.store = sessionStore;
        console.log('✅ MySQL session store initialized');
    } catch (err) {
        console.error('❌ Failed to initialize MySQL session store:', err);
        console.log('⚠️ Falling back to memory store - NOT RECOMMENDED FOR PRODUCTION');
    }
} else {
    console.log('⚠️ Using memory session store - not recommended for production');
}

app.use(session(sessionOptions));

// Register API routes with authentication middleware
app.use('/api', (req, res, next) => {
    // Skip authentication for login and auth check endpoints
    if (req.path === '/login' || req.path === '/check-auth') {
        return next();
    }
    
    // Apply authentication middleware
    authenticateUser(req, res, next);
});

// Authentication middleware
const authenticateUser = async (req, res, next) => {
    // Skip authentication for login page and API
    if (req.path === '/login' || req.path === '/api/login' || req.path === '/api/check-auth') {
        return next();
    }
    
    // Check for valid session
    if (!req.session.userId) {
        if (req.path.startsWith('/api/')) {
            return res.status(401).json({ error: 'Authentication required' });
        } else {
            return res.redirect('/login');
        }
    }
    
    // If user object is already set, use it
    if (req.user) {
        return next();
    }
    
    // Verify user exists in database
    try {
        if (!dbPool) {
            // If no database, add mock admin user
            req.user = {
                id: 0,
                username: 'admin',
                role: 'admin'
            };
            return next();
        }
        
        const [users] = await dbPool.query('SELECT * FROM users WHERE id = ?', [req.session.userId]);
        if (users.length === 0) {
            req.session.destroy();
            if (req.path.startsWith('/api/')) {
                return res.status(401).json({ error: 'Invalid session' });
            } else {
                return res.redirect('/login');
            }
        }
        
        // Add user to request object
        req.user = users[0];
        next();
    } catch (error) {
        console.error('Authentication error:', error);
        if (req.path.startsWith('/api/')) {
            return res.status(500).json({ error: 'Authentication error' });
        } else {
            return res.redirect('/login');
        }
    }
};

// Express middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// Serve login page
app.get('/login', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Serve main page
app.get('/', authenticateUser, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// NO LONGER APPLYING AUTHENTICATION MIDDLEWARE GLOBALLY
// Instead, we're applying it to specific routes as needed

// WebSocket server
const wss = new WebSocket.Server({ server: server });
const clientMap = new Map(); // ws => client_id
const clientDetails = new Map(); // client_id => details

// Tulis header kalau file belum ada
if (!fs.existsSync(logPath)) {
    fs.writeFileSync(logPath, 'timestamp,source_ip,forwarded_to,total_clients,message\n');
}

if (!fs.existsSync(receivedIpsLogPath)) {
    fs.writeFileSync(receivedIpsLogPath, 'timestamp,ip,source_client,action\n');
}

// Heartbeat interval to check for stale connections
const HEARTBEAT_INTERVAL = 30000; // 30 seconds
setInterval(() => {
    wss.clients.forEach(ws => {
        if (ws.isAlive === false) {
            const clientId = clientMap.get(ws);
            if (clientId) {
                updateClientStatus(clientId, 'offline');
                console.log(`❌ Client timed out: ${clientId}`);
            }
            return ws.terminate();
        }
        
        ws.isAlive = false;
        ws.send(JSON.stringify({
            type: 'HEARTBEAT_ACK',
            timestamp: new Date().toISOString()
        }));
    });
}, HEARTBEAT_INTERVAL);

wss.on('connection', (ws, req) => {
    ws.isAlive = true;
    const clientIp = req.socket.remoteAddress;
    console.log(`✅ Client connected: ${clientIp}`);

    ws.on('message', async (message) => {
        const timestamp = new Date().toISOString();
        const totalClients = wss.clients.size;

        try {
            const data = JSON.parse(message);
            const clientId = data.client_id || clientMap.get(ws) || 'unknown';

            if (!validateMessage(data)) {
                console.warn(`[⚠️] Invalid message from ${clientId}: `, data);
                return; // Ignore invalid messages
            }

            // Handle heartbeat
            if (data.type === 'HEARTBEAT') {
                ws.isAlive = true;
                ws.send(JSON.stringify({
                    type: 'HEARTBEAT_ACK',
                    timestamp: new Date().toISOString()
                }));
                
                // Update last seen time
                updateClientLastSeen(clientId);
                return;
            }

            // Process REGISTER
            if (data.type === 'REGISTER') {
                clientMap.set(ws, clientId);
                clientDetails.set(clientId, { 
                    ip: clientIp, 
                    connected: new Date(), 
                    status: 'online',
                    version: data.version || 'unknown'
                });
                
                // Store client in database
                await registerClient(clientId, clientIp, data.version);
                
                console.log(`🆔 Client registered: ${clientId}`);
                return;
            }                // Process BLOCK_IP
            if (data.type === 'BLOCK_IP') {
                const blockStartTime = Date.now();
                const ip = data.ip;
                
                // Log received IP
                fs.appendFileSync(
                    receivedIpsLogPath, 
                    `${timestamp},${ip},${clientId},BLOCK\n`
                );
                
                // Store blocked IP in database
                await recordBlockedIP(ip, clientId, data.source || 'client');
                
                // Alert via Discord webhook if configured
                if (discordWebhookUrl) {
                    sendDiscordAlert({
                        title: 'IP Blocked',
                        description: `IP ${ip} blocked by ${clientId}`,
                        color: 0xff0000 // Red
                    });
                }
                
                // Add request ID to track responses from clients
                const requestId = uuidv4();
                
                // Modify the payload to include the request ID
                const originalData = {...data};
                originalData.requestId = requestId;
                const payload = JSON.stringify(originalData);
                
                let forwardedCount = 0;
                
                // Track which clients we've sent this request to
                const pendingResponses = new Map();

                wss.clients.forEach(client => {
                    if (client !== ws && client.readyState === WebSocket.OPEN) {
                        // Store the client's ID and the time we sent the request
                        const receivingClientId = clientMap.get(client);
                        if (receivingClientId) {
                            pendingResponses.set(receivingClientId, Date.now());
                            forwardedCount++;
                        }
                        client.send(payload);
                    }
                });

                // Store pending response tracking info
                if (pendingResponses.size > 0) {
                    // Store the pending responses in a global map
                    pendingBlockRequests.set(requestId, {
                        ip,
                        action: 'block',
                        pendingClients: pendingResponses,
                        initiatingClient: clientId,
                        timestamp: Date.now()
                    });
                    
                    // Set a timeout to clean up any requests that don't get responses
                    setTimeout(() => {
                        cleanupPendingRequest(requestId);
                    }, REQUEST_TIMEOUT);
                }

                const responseTime = Date.now() - blockStartTime;
                
                // Immediately record a success for the initiating client
                // Since it's already blocking the IP locally (via fail2ban-trigger.sh or directly)
                await recordBlockEvent(
                    ip,
                    clientId,
                    'block',
                    true, // Assume success
                    null,
                    responseTime
                );
                
                // Don't add the initiating client to pending responses
                // This prevents the timeout since we won't expect a response from the client that sent the request

                const logLine = `${timestamp},${clientId},${forwardedCount},${totalClients},${data.type}:${data.ip}\n`;
                fs.appendFileSync(logPath, logLine);
                console.log(`📩 BLOCK_IP from ${clientId} forwarded to ${forwardedCount}/${totalClients-1} other clients (${responseTime}ms)`);
            }
            
            // Process UNBLOCK_IP
            if (data.type === 'UNBLOCK_IP') {
                const unblockStartTime = Date.now();
                const ip = data.ip;
                
                // Log received IP
                fs.appendFileSync(
                    receivedIpsLogPath, 
                    `${timestamp},${ip},${clientId},UNBLOCK\n`
                );
                
                // Update blocked IP status in database
                await updateBlockedIPStatus(ip, 'inactive');
                
                // Alert via Discord webhook if configured
                if (discordWebhookUrl) {
                    sendDiscordAlert({
                        title: 'IP Unblocked',
                        description: `IP ${ip} unblocked by ${clientId}`,
                        color: 0x00ff00 // Green
                    });
                }
                
                // Add request ID to track responses from clients
                const requestId = uuidv4();
                
                // Modify the payload to include the request ID
                const originalData = {...data};
                originalData.requestId = requestId;
                const payload = JSON.stringify(originalData);
                
                let forwardedCount = 0;
                
                // Track which clients we've sent this request to
                const pendingResponses = new Map();

                wss.clients.forEach(client => {
                    if (client !== ws && client.readyState === WebSocket.OPEN) {
                        // Store the client's ID and the time we sent the request
                        const receivingClientId = clientMap.get(client);
                        if (receivingClientId) {
                            pendingResponses.set(receivingClientId, Date.now());
                            forwardedCount++;
                        }
                        client.send(payload);
                    }
                });

                // Store pending response tracking info
                if (pendingResponses.size > 0) {
                    // Store the pending responses in a global map
                    pendingBlockRequests.set(requestId, {
                        ip,
                        action: 'unblock',
                        pendingClients: pendingResponses,
                        initiatingClient: clientId,
                        timestamp: Date.now()
                    });
                    
                    // Set a timeout to clean up any requests that don't get responses
                    setTimeout(() => {
                        cleanupPendingRequest(requestId);
                    }, REQUEST_TIMEOUT);
                }

                const responseTime = Date.now() - unblockStartTime;
                
                // Immediately record a success for the initiating client
                // Since it's already unblocking the IP locally
                await recordBlockEvent(
                    ip,
                    clientId,
                    'unblock',
                    true, // Assume success
                    null,
                    responseTime
                );
                
                // Don't add the initiating client to pending responses
                // This prevents the timeout since we won't expect a response from the client that sent the request

                console.log(`📩 UNBLOCK_IP from ${clientId} forwarded to ${forwardedCount}/${totalClients-1} other clients (${responseTime}ms)`);
            }
            
            // Process BLOCK_RESULT
            if (data.type === 'BLOCK_RESULT' || data.type === 'UNBLOCK_RESULT') {
                const action = data.type === 'BLOCK_RESULT' ? 'block' : 'unblock';
                const requestId = data.requestId;
                
                // Check if this is a response to a tracked request
                if (requestId && pendingBlockRequests.has(requestId)) {
                    const request = pendingBlockRequests.get(requestId);
                    
                    // If this client was in the pending list
                    if (request.pendingClients.has(clientId)) {
                        // Calculate response time
                        const sentTime = request.pendingClients.get(clientId);
                        const responseTime = Date.now() - sentTime;
                        
                        // Record the block event with the response time
                        await recordBlockEvent(
                            data.ip, 
                            clientId, 
                            action,
                            data.success, 
                            data.error || null, 
                            responseTime
                        );
                        
                        // Remove this client from the pending list
                        request.pendingClients.delete(clientId);
                        
                        // If all clients have responded, remove the request
                        if (request.pendingClients.size === 0) {
                            pendingBlockRequests.delete(requestId);
                        }
                        
                        console.log(`📊 ${action.toUpperCase()} response from ${clientId} for IP ${data.ip}: ${data.success ? 'Success' : 'Failed'} (${responseTime}ms)`);
                    } else {
                        // This is a response from a client we weren't tracking
                        // Instead of NULL, use current time as a baseline
                        const responseTime = 0; // We don't know when the request was sent, so use 0 as a fallback
                        
                        await recordBlockEvent(
                            data.ip, 
                            clientId, 
                            action,
                            data.success, 
                            data.error || null, 
                            responseTime
                        );
                        
                        console.log(`📊 ${action.toUpperCase()} response from ${clientId} for IP ${data.ip} (untracked client): ${data.success ? 'Success' : 'Failed'}`);
                    }
                } else {
                    // This is for an untracked request (e.g., from a client action not initiated by the server)
                    // Instead of NULL, use 0 as a fallback response time
                    const responseTime = 0;
                    
                    await recordBlockEvent(
                        data.ip, 
                        clientId, 
                        action,
                        data.success, 
                        data.error || null, 
                        responseTime
                    );
                    
                    console.log(`📊 ${action.toUpperCase()} response from ${clientId} for IP ${data.ip} (untracked request): ${data.success ? 'Success' : 'Failed'}`);
                }
                
                if (!data.success && discordWebhookUrl) {
                    sendDiscordAlert({
                        title: `${action.charAt(0).toUpperCase() + action.slice(1)} Failed`,
                        description: `Failed to ${action} IP ${data.ip} on client ${clientId}: ${data.error}`,
                        color: 0xffff00 // Yellow for warnings
                    });
                }
            }
            
            // Process METRICS
            if (data.type === 'METRICS' && data.metrics) {
                await storeMetrics(clientId, data.metrics);
            }
        } catch (e) {
            console.error(`[❌] Failed to parse JSON from client:`, e.message);
        }
    });

    ws.on('close', async () => {
        const clientId = clientMap.get(ws);
        if (clientId) {
            console.log(`❌ Client disconnected: ${clientId}`);
            await updateClientStatus(clientId, 'offline');
            clientMap.delete(ws);
        } else {
            console.log(`❌ Unknown client disconnected: ${clientIp}`);
        }
    });

    ws.on('error', (error) => {
        console.error(`[❌] WebSocket error:`, error.message);
    });
});

// API Endpoints for Admin Dashboard
app.get('/api/clients', async (req, res) => {
    try {
        const clients = await getClients();
        res.json(clients);
    } catch (error) {
        console.error('Error fetching clients:', error);
        res.status(500).json({ error: 'Failed to fetch clients' });
    }
});

app.get('/api/blocked-ips', async (req, res) => {
    try {
        const blockedIPs = await getBlockedIPs();
        res.json(blockedIPs);
    } catch (error) {
        console.error('Error fetching blocked IPs:', error);
        res.status(500).json({ error: 'Failed to fetch blocked IPs' });
    }
});

app.post('/api/block-ip', async (req, res) => {
    try {
        const { ip } = req.body;
        
        if (!ip || !isValidIP(ip)) {
            return res.status(400).json({ error: 'Invalid IP address' });
        }
        
        // Record in database
        await recordBlockedIP(ip, 'admin', 'manual');
        
        // Generate a request ID for tracking responses
        const requestId = uuidv4();
        
        // Broadcast to all clients
        const blockMessage = JSON.stringify({
            type: 'BLOCK_IP',
            client_id: 'admin',
            token: process.env.SECRET_TOKEN,
            ip: ip,
            source: 'manual',
            requestId: requestId,
            timestamp: new Date().toISOString()
        });
        
        // Track which clients we've sent this request to
        const pendingResponses = new Map();
        let sentCount = 0;
        
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                // Store the client's ID and the time we sent the request
                const receivingClientId = clientMap.get(client);
                if (receivingClientId) {
                    pendingResponses.set(receivingClientId, Date.now());
                    sentCount++;
                }
                client.send(blockMessage);
            }
        });
        
        // Store pending response tracking info
        if (pendingResponses.size > 0) {
            // Store the pending responses in a global map
            pendingBlockRequests.set(requestId, {
                ip,
                action: 'block',
                pendingClients: pendingResponses,
                initiatingClient: 'admin',
                timestamp: Date.now()
            });
            
            // Set a timeout to clean up any requests that don't get responses
            setTimeout(() => {
                cleanupPendingRequest(requestId);
            }, REQUEST_TIMEOUT);
        }
        
        // For manual admin actions, we don't need to record an event for the admin
        // since they aren't a client that will perform the block operation.
        // The actual block events will be recorded when clients respond with BLOCK_RESULT
        
        res.json({ 
            success: true, 
            message: `Blocking request for IP ${ip} sent to ${sentCount} clients` 
        });
    } catch (error) {
        console.error('Error blocking IP:', error);
        res.status(500).json({ error: 'Failed to block IP' });
    }
});

app.post('/api/unblock-ip', async (req, res) => {
    try {
        const { ip } = req.body;
        
        if (!ip || !isValidIP(ip)) {
            return res.status(400).json({ error: 'Invalid IP address' });
        }
        
        // Update database
        await updateBlockedIPStatus(ip, 'inactive');
        
        // Generate a request ID for tracking responses
        const requestId = uuidv4();
        
        // Broadcast to all clients
        const unblockMessage = JSON.stringify({
            type: 'UNBLOCK_IP',
            client_id: 'admin',
            token: process.env.SECRET_TOKEN,
            ip: ip,
            requestId: requestId,
            timestamp: new Date().toISOString()
        });
        
        // Track which clients we've sent this request to
        const pendingResponses = new Map();
        let sentCount = 0;
        
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                // Store the client's ID and the time we sent the request
                const receivingClientId = clientMap.get(client);
                if (receivingClientId) {
                    pendingResponses.set(receivingClientId, Date.now());
                    sentCount++;
                }
                client.send(unblockMessage);
            }
        });
        
        // Store pending response tracking info
        if (pendingResponses.size > 0) {
            // Store the pending responses in a global map
            pendingBlockRequests.set(requestId, {
                ip,
                action: 'unblock',
                pendingClients: pendingResponses,
                initiatingClient: 'admin',
                timestamp: Date.now()
            });
            
            // Set a timeout to clean up any requests that don't get responses
            setTimeout(() => {
                cleanupPendingRequest(requestId);
            }, REQUEST_TIMEOUT);
        }
        
        // For manual admin actions, we don't need to record an event for the admin
        // since they aren't a client that will perform the unblock operation.
        // The actual unblock events will be recorded when clients respond with UNBLOCK_RESULT
        
        res.json({ 
            success: true, 
            message: `Unblocking request for IP ${ip} sent to ${sentCount} clients` 
        });
    } catch (error) {
        console.error('Error unblocking IP:', error);
        res.status(500).json({ error: 'Failed to unblock IP' });
    }
});

app.get('/api/metrics', async (req, res) => {
    try {
        const metrics = await getMetrics();
        res.json(metrics);
    } catch (error) {
        console.error('Error fetching metrics:', error);
        res.status(500).json({ error: 'Failed to fetch metrics' });
    }
});

app.get('/api/block-events', async (req, res) => {
    try {
        const blockEvents = await getBlockEvents();
        res.json(blockEvents);
    } catch (error) {
        console.error('Error fetching block events:', error);
        res.status(500).json({ error: 'Failed to fetch block events' });
    }
});

app.get('/api/stats', async (req, res) => {
    try {
        const totalClients = await getTotalClients();
        const activeClients = await getActiveClients();
        const totalBlockedIPs = await getTotalBlockedIPs();
        const activeBlockedIPs = await getActiveBlockedIPs();
        const totalBlockEvents = await getTotalBlockEvents();
        
        res.json({
            totalClients,
            activeClients,
            totalBlockedIPs,
            activeBlockedIPs,
            totalBlockEvents
        });
    } catch (error) {
        console.error('Error fetching stats:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// Authentication routes
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }
        
        // If database is not available, use hard-coded admin credentials
        if (!dbPool) {
            const defaultPassword = process.env.DEFAULT_ADMIN_PASSWORD || 'admin123';
            
            if (username === 'admin' && password === defaultPassword) {
                // Set session values
                req.session.userId = 0;
                req.session.username = 'admin';
                req.session.role = 'admin';
                
                // Also set the user object directly
                req.user = {
                    id: 0,
                    username: 'admin',
                    role: 'admin'
                };
                
                // Save session explicitly to ensure it's stored
                req.session.save(err => {
                    if (err) {
                        console.error('Error saving session:', err);
                        return res.status(500).json({ error: 'Session error' });
                    }
                    
                    return res.json({ 
                        success: true, 
                        username: 'admin', 
                        role: 'admin' 
                    });
                });
                return;
            } else {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
        }
        
        // Check user credentials in database
        const [users] = await dbPool.query('SELECT * FROM users WHERE username = ?', [username]);
        
        if (users.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const user = users[0];
        const passwordMatch = await bcrypt.compare(password, user.password);
        
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Update last login timestamp
        await dbPool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
        
        // Set session
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.role = user.role;
        
        // Record session in database
        const sessionId = uuidv4();
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
        
        await dbPool.query(
            'INSERT INTO sessions (session_id, user_id, ip_address, user_agent, expires_at) VALUES (?, ?, ?, ?, ?)',
            [
                sessionId,
                user.id,
                req.ip,
                req.headers['user-agent'],
                expiresAt
            ]
        );
        
        res.json({
            success: true,
            username: user.username,
            role: user.role
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Authentication error' });
    }
});

app.post('/api/logout', (req, res) => {
    if (req.session) {
        // Get session cookie settings to match them on clearCookie
        const cookieOptions = req.session.cookie || {};
        const cookieSettings = {
            path: '/',
            httpOnly: cookieOptions.httpOnly || true,
            secure: cookieOptions.secure || false,
            sameSite: cookieOptions.sameSite || 'lax'
        };

        req.session.destroy((err) => {
            if (err) {
                console.error('Error destroying session:', err);
                return res.status(500).json({ error: 'Logout failed' });
            }
            
            // Clear cookie with matching settings
            res.clearCookie('connect.sid', cookieSettings);
            res.json({ success: true });
        });
    } else {
        // Session already gone
        res.clearCookie('connect.sid', {
            path: '/',
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production' && process.env.DISABLE_SECURE_COOKIE !== 'true',
            sameSite: 'lax'
        });
        res.json({ success: true });
    }
});

app.get('/api/check-auth', (req, res) => {
    if (req.session && req.session.userId !== undefined) {
        const role = req.session.role || (!dbPool ? 'admin' : 'user'); // Default to admin in memory-only mode
        const username = req.session.username || 'admin';
        
        // If in memory-only mode and userId is 0, ensure the admin role is set
        if (!dbPool && req.session.userId === 0 && role !== 'admin') {
            req.session.role = 'admin';
        }
        
        res.json({
            authenticated: true,
            username: username,
            role: role
        });
    } else {
        res.json({ authenticated: false });
    }
});

// User management routes
app.get('/api/users', async (req, res) => {
    try {
        // Direct session check without relying on user object from middleware
        if (!req.session || !req.session.userId) {
            return res.status(401).json({ 
                error: 'Authentication required'
            });
        }
        
        // Get user information directly from the session or database
        let user;
        
        // In memory-only mode, create user from session
        if (!dbPool) {
            user = {
                id: req.session.userId,
                username: req.session.username || 'admin',
                role: req.session.role || 'admin'
            };
        } else {
            // In database mode, fetch user from database
            const [users] = await dbPool.query('SELECT * FROM users WHERE id = ?', [req.session.userId]);
            if (users.length === 0) {
                return res.status(401).json({ 
                    error: 'Invalid session'
                });
            }
            user = users[0];
        }
        
        // Check if user is admin
        if (user.role !== 'admin') {
            return res.status(403).json({ 
                error: 'Unauthorized',
                reason: `User is not admin (role: ${user.role})`
            });
        }
        
        if (!dbPool) {
            // Return a mock admin user when in memory-only mode
            return res.json([{ 
                id: 0, 
                username: 'admin', 
                role: 'admin', 
                created_at: new Date().toISOString(),
                last_login: new Date().toISOString()
            }]);
        }
        
        const [users] = await dbPool.query(
            'SELECT id, username, email, role, created_at, last_login FROM users ORDER BY id'
        );
        
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ 
            error: 'Failed to fetch users', 
            message: error.message 
        });
    }
});

app.post('/api/users', async (req, res) => {
    try {
        // Direct session check without relying on user object from middleware
        if (!req.session || !req.session.userId) {
            return res.status(401).json({ 
                error: 'Authentication required'
            });
        }
        
        // Get user role directly from the session or database
        let userRole;
        
        if (!dbPool) {
            userRole = req.session.role || 'admin';
        } else {
            const [users] = await dbPool.query('SELECT role FROM users WHERE id = ?', [req.session.userId]);
            if (users.length === 0) {
                return res.status(401).json({ error: 'Invalid session' });
            }
            userRole = users[0].role;
        }
        
        // Check if user is admin
        if (userRole !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        
        const { username, password, email, role } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }
        
        if (!dbPool) {
            return res.status(503).json({ error: 'Database not available' });
        }
        
        // Check if username already exists
        const [existingUsers] = await dbPool.query('SELECT id FROM users WHERE username = ?', [username]);
        if (existingUsers.length > 0) {
            return res.status(400).json({ error: 'Username already exists' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create user
        const [result] = await dbPool.query(
            'INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
            [username, hashedPassword, email, role || 'user']
        );
        
        res.json({ 
            success: true, 
            userId: result.insertId,
            message: 'User created successfully'
        });
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({ error: 'Failed to create user' });
    }
});

app.put('/api/users/:id', async (req, res) => {
    try {
        // Direct session check without relying on user object from middleware
        if (!req.session || !req.session.userId) {
            return res.status(401).json({ 
                error: 'Authentication required'
            });
        }
        
        // Get user role directly from the session or database
        let userRole;
        
        if (!dbPool) {
            userRole = req.session.role || 'admin';
        } else {
            const [users] = await dbPool.query('SELECT role FROM users WHERE id = ?', [req.session.userId]);
            if (users.length === 0) {
                return res.status(401).json({ error: 'Invalid session' });
            }
            userRole = users[0].role;
        }
        
        // Check if user is admin
        if (userRole !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        
        const userId = req.params.id;
        const { username, password, email, role } = req.body;
        
        if (!dbPool) {
            return res.status(503).json({ error: 'Database not available' });
        }
        
        // Check if user exists
        const [existingUsers] = await dbPool.query('SELECT id FROM users WHERE id = ?', [userId]);
        if (existingUsers.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Update user
        let query = 'UPDATE users SET ';
        const params = [];
        
        if (username) {
            query += 'username = ?, ';
            params.push(username);
        }
        
        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            query += 'password = ?, ';
            params.push(hashedPassword);
        }
        
        if (email !== undefined) {
            query += 'email = ?, ';
            params.push(email);
        }
        
        if (role) {
            query += 'role = ?, ';
            params.push(role);
        }
        
        // Remove trailing comma and space
        query = query.slice(0, -2);
        
        query += ' WHERE id = ?';
        params.push(userId);
        
        await dbPool.query(query, params);
        
        res.json({ 
            success: true, 
            message: 'User updated successfully'
        });
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ error: 'Failed to update user' });
    }
});

app.delete('/api/users/:id', async (req, res) => {
    try {
        // Direct session check without relying on user object from middleware
        if (!req.session || !req.session.userId) {
            return res.status(401).json({ 
                error: 'Authentication required'
            });
        }
        
        // Get user info directly from the session or database
        let user;
        
        if (!dbPool) {
            user = {
                id: req.session.userId,
                role: req.session.role || 'admin'
            };
        } else {
            const [users] = await dbPool.query('SELECT id, role FROM users WHERE id = ?', [req.session.userId]);
            if (users.length === 0) {
                return res.status(401).json({ error: 'Invalid session' });
            }
            user = users[0];
        }
        
        // Check if user is admin
        if (user.role !== 'admin') {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        
        const userId = req.params.id;
        
        // Prevent deleting own account
        if (parseInt(userId) === user.id) {
            return res.status(400).json({ error: 'Cannot delete your own account' });
        }
        
        if (!dbPool) {
            return res.status(503).json({ error: 'Database not available' });
        }
        
        // Delete user
        await dbPool.query('DELETE FROM users WHERE id = ?', [userId]);
        
        res.json({ 
            success: true, 
            message: 'User deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// API Routes

// Get total blocks for a specific client
app.get('/api/client/:clientId/totalBlocks', async (req, res) => {
    try {
        const clientId = req.params.clientId;
        
        if (!dbPool) {
            return res.status(500).json({ error: 'Database not available' });
        }
        
        // Get current total blocks for this client
        const [result] = await dbPool.query(
            `SELECT total_blocks FROM metrics WHERE client_id = ?`,
            [clientId]
        );
        
        if (result.length > 0) {
            res.json({ total_blocks: result[0].total_blocks });
        } else {
            res.json({ total_blocks: 0 });
        }
    } catch (error) {
        console.error('Error getting total blocks:', error);
        res.status(500).json({ error: 'Failed to get total blocks' });
    }
});

// Database functions
async function registerClient(clientId, clientIp, version = 'unknown') {
    if (!dbPool) return;
    
    try {
        await dbPool.query(`
            INSERT INTO clients (id, ip, status, version) 
            VALUES (?, ?, 'online', ?)
            ON DUPLICATE KEY UPDATE 
                last_seen = CURRENT_TIMESTAMP,
                status = 'online',
                ip = ?,
                version = ?
        `, [clientId, clientIp, version, clientIp, version]);
    } catch (error) {
        console.error(`Error registering client ${clientId}:`, error);
    }
}

async function updateClientLastSeen(clientId) {
    if (!dbPool) return;
    
    try {
        await dbPool.query(`
            UPDATE clients 
            SET last_seen = CURRENT_TIMESTAMP 
            WHERE id = ?
        `, [clientId]);
    } catch (error) {
        console.error(`Error updating last seen for client ${clientId}:`, error);
    }
}

async function updateClientStatus(clientId, status) {
    if (!dbPool) return;
    
    try {
        await dbPool.query(`
            UPDATE clients 
            SET status = ?, last_seen = CURRENT_TIMESTAMP 
            WHERE id = ?
        `, [status, clientId]);
    } catch (error) {
        console.error(`Error updating status for client ${clientId}:`, error);
    }
}

async function recordBlockedIP(ip, clientId, source = 'unknown') {
    if (!dbPool) return;
    
    try {
        await dbPool.query(`
            INSERT INTO blocked_ips (ip, source, status) 
            VALUES (?, ?, 'active')
            ON DUPLICATE KEY UPDATE 
                last_blocked = CURRENT_TIMESTAMP,
                status = 'active',
                block_count = block_count + 1
        `, [ip, source]);
    } catch (error) {
        console.error(`Error recording blocked IP ${ip}:`, error);
    }
}

async function updateBlockedIPStatus(ip, status) {
    if (!dbPool) return;
    
    try {
        await dbPool.query(`
            UPDATE blocked_ips 
            SET status = ? 
            WHERE ip = ?
        `, [status, ip]);
    } catch (error) {
        console.error(`Error updating status for IP ${ip}:`, error);
    }
}

async function recordBlockEvent(ip, clientId, action, success, errorMessage = null, responseTime = null) {
    if (!dbPool) return;
    
    try {
        await dbPool.query(`
            INSERT INTO block_events 
            (ip, client_id, action, success, error_message, response_time_ms) 
            VALUES (?, ?, ?, ?, ?, ?)
        `, [ip, clientId, action, success, errorMessage, responseTime]);
    } catch (error) {
        console.error(`Error recording block event for IP ${ip}:`, error);
    }
}

async function storeMetrics(clientId, metrics) {
    if (!dbPool) return;
    
    try {
        const memoryUsageMB = metrics.memoryUsage && metrics.memoryUsage.heapUsed 
            ? Math.round(metrics.memoryUsage.heapUsed / 1024 / 1024 * 100) / 100
            : null;

        // Get current total blocks for this client
        const [currentMetrics] = await dbPool.query(`
            SELECT client_id, total_blocks, blocks_per_minute FROM metrics WHERE client_id = ?
        `, [clientId]);
        
        // Get the client's reported total blocks or default to 0
        let clientReportedTotal = metrics.totalLocalBlocks || 0;
        let blocksPerMinute = metrics.lastMinuteBlockCount || 0;
        let finalTotalBlocks = clientReportedTotal;
        
        // If client exists in the metrics table, determine the correct total
        if (currentMetrics.length > 0) {
            const dbStoredTotal = currentMetrics[0].total_blocks || 0;
            
            // Always use the higher value between what's in the database and what the client reports
            // This ensures we don't lose counts if the client restarts
            finalTotalBlocks = Math.max(clientReportedTotal, dbStoredTotal);
            
            // If the client just connected (totalLocalBlocks is 0), use the stored total
            if (clientReportedTotal === 0 && dbStoredTotal > 0) {
                finalTotalBlocks = dbStoredTotal;
            }
            
            // Calculate new average blocks per minute (rolling average)
            // 80% of previous average + 20% of new value
            blocksPerMinute = (currentMetrics[0].blocks_per_minute * 0.8) + 
                              (metrics.lastMinuteBlockCount * 0.2);
        }
            
        // Check if the client exists in metrics table
        const [clientExists] = await dbPool.query(`
            SELECT COUNT(*) as count FROM metrics WHERE client_id = ?
        `, [clientId]);
        
        if (clientExists[0].count > 0) {
            // Client exists, perform UPDATE only
            await dbPool.query(`
                UPDATE metrics SET 
                    blocks_last_minute = ?,
                    blocks_per_minute = ?,
                    total_blocks = ?,
                    uptime_seconds = ?,
                    memory_usage_mb = ?,
                    last_reported = NOW()
                WHERE client_id = ?
            `, [
                metrics.lastMinuteBlockCount || 0,
                blocksPerMinute,
                finalTotalBlocks,
                metrics.uptime || 0,
                memoryUsageMB,
                clientId
            ]);
        } else {
            // Client doesn't exist, perform INSERT
            await dbPool.query(`
                INSERT INTO metrics 
                (client_id, blocks_last_minute, blocks_per_minute, total_blocks, uptime_seconds, memory_usage_mb, last_reported) 
                VALUES (?, ?, ?, ?, ?, ?, NOW())
            `, [
                clientId, 
                metrics.lastMinuteBlockCount || 0,
                blocksPerMinute,
                finalTotalBlocks,
                metrics.uptime || 0,
                memoryUsageMB
            ]);
        }
        
        console.log(`📊 Metrics updated for client ${clientId}: ${metrics.lastMinuteBlockCount} blocks in last minute, ${finalTotalBlocks} total blocks`);
    } catch (error) {
        console.error(`Error storing metrics for client ${clientId}:`, error);
    }
}

// Query functions for API
async function getClients() {
    if (!dbPool) {
        // Return in-memory data if no database
        return Array.from(clientDetails.entries()).map(([id, details]) => ({
            id,
            ip: details.ip,
            status: details.status,
            last_seen: details.lastSeen || details.connected,
            first_connected: details.connected,
            version: details.version
        }));
    }
    
    const [rows] = await dbPool.query(`
        SELECT * FROM clients
        ORDER BY status ASC, last_seen DESC
    `);
    
    return rows;
}

async function getBlockedIPs() {
    if (!dbPool) {
        // We can't return much without a database
        return [];
    }
    
    const [rows] = await dbPool.query(`
        SELECT * FROM blocked_ips
        ORDER BY last_blocked DESC
    `);
    
    return rows;
}

async function getMetrics() {
    if (!dbPool) {
        // Return some mock data if no database
        return Array.from(clientDetails.entries()).map(([id, details]) => ({
            client_id: id,
            blocks_per_minute: 0,
            total_blocks: 0,
            uptime_seconds: 0,
            memory_usage_mb: 0,
            last_reported: new Date().toISOString()
        }));
    }
    
    const [rows] = await dbPool.query(`
        SELECT 
            m.client_id,
            m.blocks_per_minute,
            m.blocks_last_minute,
            m.total_blocks,
            m.uptime_seconds,
            m.memory_usage_mb,
            m.last_reported,
            c.status AS client_status
        FROM 
            metrics m
        LEFT JOIN 
            clients c ON m.client_id = c.id
        ORDER BY 
            m.total_blocks DESC
    `);
    
    // Format the rows to match what the frontend expects
    const formattedRows = rows.map(row => ({
        client_id: row.client_id,
        avg_blocks_per_minute: row.blocks_per_minute,
        blocks_last_minute: row.blocks_last_minute,
        total_blocks: row.total_blocks,
        uptime_seconds: row.uptime_seconds,
        memory_usage_mb: row.memory_usage_mb,
        latest_timestamp: row.last_reported,
        client_status: row.client_status
    }));
    
    return formattedRows;
}

async function getBlockEvents() {
    if (!dbPool) return [];
    
    const [rows] = await dbPool.query(`
        SELECT 
            be.id,
            be.ip,
            be.client_id,
            be.action,
            be.timestamp,
            be.success,
            be.error_message,
            be.response_time_ms,
            c.ip as client_ip
        FROM block_events be
        LEFT JOIN clients c ON be.client_id = c.id
        WHERE be.timestamp > DATE_SUB(NOW(), INTERVAL 7 DAY)
        ORDER BY be.timestamp DESC
        LIMIT 500
    `);
    
    return rows;
}

async function getTotalClients() {
    if (!dbPool) return clientDetails.size;
    
    const [rows] = await dbPool.query('SELECT COUNT(*) as count FROM clients');
    return rows[0].count;
}

async function getActiveClients() {
    if (!dbPool) {
        return Array.from(clientDetails.values()).filter(c => c.status === 'online').length;
    }
    
    const [rows] = await dbPool.query(`
        SELECT COUNT(*) as count FROM clients WHERE status = 'online'
    `);
    return rows[0].count;
}

async function getTotalBlockedIPs() {
    if (!dbPool) return 0;
    
    const [rows] = await dbPool.query('SELECT COUNT(*) as count FROM blocked_ips');
    return rows[0].count;
}

async function getActiveBlockedIPs() {
    if (!dbPool) return 0;
    
    const [rows] = await dbPool.query(`
        SELECT COUNT(*) as count FROM blocked_ips WHERE status = 'active'
    `);
    return rows[0].count;
}

async function getTotalBlockEvents() {
    if (!dbPool) return 0;
    
    const [rows] = await dbPool.query('SELECT COUNT(*) as count FROM block_events');
    return rows[0].count;
}

// Helper functions
function validateMessage(data) {
    // Validate message structure
    if (!data || typeof data !== 'object') return false;
    // Check required fields
    if (!data.type || !data.client_id) return false;
    // Check token matches server token (except for HEARTBEAT)
    if (data.type !== 'HEARTBEAT' && data.token !== process.env.SECRET_TOKEN) return false;

    // Check if type is valid for specific message types
    if (data.type === 'BLOCK_IP' || data.type === 'UNBLOCK_IP') {
        // Simple IPv4 validation
        if (!data.ip || !isValidIP(data.ip)) return false;
    }

    return true;
}

function isValidIP(ip) {
    // IPv4 validation
    const ipRegex = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
    return ipRegex.test(ip);
}

// Discord webhook function
async function sendDiscordAlert(alert) {
    if (!discordWebhookUrl) return;
    
    try {
        await axios.post(discordWebhookUrl, {
            embeds: [{
                title: alert.title,
                description: alert.description,
                color: alert.color || 0x0099ff,
                timestamp: new Date().toISOString()
            }]
        });
    } catch (error) {
        console.error('Failed to send Discord alert:', error.message);
    }
}

// Initialize the database and start the servers
async function start() {
    await initDatabase();
    
    server.listen(port, () => {
        console.log(`🔌 ASDA WebSocket Server running on port ${port}`);
    });
    
    // Start the web server for the dashboard
    app.listen(webPort, '0.0.0.0', () => {
        console.log(`🌐 ASDA Dashboard running on port ${webPort}`);
    });
}

start();