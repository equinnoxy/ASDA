require('dotenv').config();
const WebSocket = require('ws');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

// Configuration
const serverIp = process.env.SERVER_IP;
const serverPort = process.env.SERVER_PORT;
const clientId = process.env.CLIENT_ID;
const token = process.env.SECRET_TOKEN;
const url = `ws://${serverIp}:${serverPort}`;
const ipQueuePath = path.join(__dirname, '.ip_queue');
const logDir = path.join(__dirname, 'logs');
const actionsLogPath = path.join(logDir, 'actions.log');
const blockLogPath = path.join(logDir, 'block_log.csv');

// Ensure log directory exists
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
}

// If block_log.csv doesn't exist, create it with headers
if (!fs.existsSync(blockLogPath)) {
    fs.writeFileSync(blockLogPath, 'timestamp,ip,action,result\n');
}

// Connection management variables
let ws;
let reconnectAttempt = 0;
const MAX_RECONNECT_DELAY = 30000; // Maximum reconnection delay (30 seconds)
const INITIAL_RECONNECT_DELAY = 1000; // Initial reconnection delay (1 second)
let reconnectTimer = null;
let heartbeatInterval = null;
let missedHeartbeats = 0;
const MAX_MISSED_HEARTBEATS = 3;

// Create WebSocket connection with reconnection logic
function connect() {
    // Clear any existing connection resources
    if (ws) {
        clearInterval(heartbeatInterval);
        ws.removeAllListeners();
        try {
            ws.terminate();
        } catch (e) {
            // Ignore termination errors
        }
    }

    log('Connecting to ASDA WebSocket Server at ' + url);
    ws = new WebSocket(url);

    ws.on('open', () => {
        log(`✅ Connected to ASDA WebSocket Server at ${url}`);
        reconnectAttempt = 0; // Reset reconnect counter on successful connection
        
        // Register client
        ws.send(JSON.stringify({
            type: 'REGISTER',
            client_id: clientId,
            token: token
        }));

        // Start heartbeat
        missedHeartbeats = 0;
        clearInterval(heartbeatInterval);
        heartbeatInterval = setInterval(sendHeartbeat, 30000); // Send heartbeat every 30 seconds
    });

    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            
            // Reset missed heartbeats on any message
            missedHeartbeats = 0;
            
            if (data.type === 'HEARTBEAT_ACK') {
                // Just a heartbeat acknowledgment, no action needed
                return;
            }
            
            if (data.type === 'BLOCK_IP' && data.ip) {
                const ip = data.ip;
                const requestId = data.requestId;
                log(`🔒 Receiving blocking request for IP: ${ip} (requestId: ${requestId || 'none'})`);
                blockIP(ip, requestId);
            } else if (data.type === 'UNBLOCK_IP' && data.ip) {
                const ip = data.ip;
                const requestId = data.requestId;
                log(`� Receiving unblocking request for IP: ${ip} (requestId: ${requestId || 'none'})`);
                unblockIP(ip, requestId);
            } else {
                log(`[⚠️] Message received but not processed: ${JSON.stringify(data)}`, 'warn');
            }
        } catch (e) {
            log(`[❌] Failed to parse message: ${e.message}`, 'error');
        }
    });

    ws.on('close', () => {
        log('❌ Disconnected from server');
        scheduleReconnect();
    });

    ws.on('error', (error) => {
        log(`[❌] WebSocket error: ${error.message}`, 'error');
        // Don't call scheduleReconnect here - the close event will trigger
    });
}

// Reconnection logic with exponential backoff
function scheduleReconnect() {
    if (reconnectTimer) {
        clearTimeout(reconnectTimer);
    }
    
    // Calculate backoff time with jitter
    const delay = Math.min(
        INITIAL_RECONNECT_DELAY * Math.pow(1.5, reconnectAttempt) + Math.random() * 1000,
        MAX_RECONNECT_DELAY
    );
    
    log(`Attempting to reconnect in ${Math.round(delay / 1000)} seconds (attempt ${reconnectAttempt + 1})...`);
    
    reconnectTimer = setTimeout(() => {
        reconnectAttempt++;
        connect();
    }, delay);
}

// Send heartbeat to check connection
function sendHeartbeat() {
    if (ws.readyState === WebSocket.OPEN) {
        missedHeartbeats++;
        if (missedHeartbeats >= MAX_MISSED_HEARTBEATS) {
            log('[⚠️] Server not responding to heartbeats, reconnecting...', 'warn');
            ws.terminate();
            scheduleReconnect();
            return;
        }
        
        ws.send(JSON.stringify({
            type: 'HEARTBEAT',
            client_id: clientId,
            token: token
        }));
    }
}

// Block an IP address
function blockIP(ip, requestId) {
    if (!isValidIP(ip)) {
        log(`[❌] Invalid IP format: ${ip}`, 'error');
        reportError('BLOCK_IP', ip, 'Invalid IP format', requestId);
        return;
    }

    // Debug logging for troubleshooting
    log(`[🔍] Starting block operation for IP: ${ip} (requestId: ${requestId || 'none'})`);

    const command = `bash "${path.join(__dirname, 'block_from_server.sh')}" "${ip}" "client-js" "120"`;
    log(`[🔄] Executing command: ${command}`);
    
    // Execute blocking script with better error handling
    exec(command, { maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
        if (err) {
            log(`[❌] Failed to execute IP block: Exit code ${err.code}`, 'error');
            log(`[❌] Command output: ${stdout}`, 'error');
            log(`[❌] Error output: ${stderr}`, 'error');
            reportError('BLOCK_IP', ip, stderr || stdout || `Exit code ${err.code}`, requestId);
            return;
        }
        
        // Log all script output for debugging
        if (stdout) {
            log(`[🔍] Block script stdout: ${stdout.trim()}`);
        }
        if (stderr) {
            log(`[🔍] Block script stderr: ${stderr.trim()}`, stderr ? 'warn' : 'info');
        }
        
        log(`[✅] Successfully blocked IP: ${ip}`);
        
        // Report success to server
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
                type: 'BLOCK_RESULT',
                client_id: clientId,
                token: token,
                ip: ip,
                requestId: requestId,
                success: true,
                timestamp: new Date().toISOString()
            }));
        }
    });
}

// Unblock an IP address
function unblockIP(ip, requestId) {
    if (!isValidIP(ip)) {
        log(`[❌] Invalid IP format: ${ip}`, 'error');
        reportError('UNBLOCK_IP', ip, 'Invalid IP format', requestId);
        return;
    }

    // Debug logging for troubleshooting
    log(`[🔍] Starting unblock operation for IP: ${ip} (requestId: ${requestId || 'none'})`);

    const command = `bash "${path.join(__dirname, 'unblock_from_server.sh')}" "${ip}"`;
    log(`[🔄] Executing command: ${command}`);
    
    // Execute unblocking script with better error handling
    exec(command, { maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
        if (err) {
            log(`[❌] Failed to execute IP unblock: Exit code ${err.code}`, 'error');
            log(`[❌] Command output: ${stdout}`, 'error');
            log(`[❌] Error output: ${stderr}`, 'error');
            reportError('UNBLOCK_IP', ip, stderr || stdout || `Exit code ${err.code}`, requestId);
            return;
        }
        
        // Log all script output for debugging
        if (stdout) {
            log(`[🔍] Unblock script stdout: ${stdout.trim()}`);
        }
        if (stderr) {
            log(`[🔍] Unblock script stderr: ${stderr.trim()}`, stderr ? 'warn' : 'info');
        }
        
        log(`[✅] Successfully unblocked IP: ${ip}`);
        
        // Report success to server
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
                type: 'UNBLOCK_RESULT',
                client_id: clientId,
                token: token,
                ip: ip,
                requestId: requestId,
                success: true,
                timestamp: new Date().toISOString()
            }));
        }
    });
}

// Report errors back to the server
function reportError(operation, ip, errorMessage, requestId) {
    if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            type: `${operation}_RESULT`,
            client_id: clientId,
            token: token,
            ip: ip,
            requestId: requestId,
            success: false,
            error: errorMessage,
            timestamp: new Date().toISOString()
        }));
    }
    
    // Log to CSV
    const timestamp = new Date().toISOString();
    const logLine = `${timestamp},${ip},${operation},ERROR,"${errorMessage}"\n`;
    fs.appendFileSync(blockLogPath, logLine);
}

// Validate IP address format
function isValidIP(ip) {
    // Simple IPv4 validation
    const ipRegex = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
    return ipRegex.test(ip);
}

// Generate a unique request ID (similar to UUID v4)
function generateRequestId() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

// Enhanced logging function
function log(message, level = 'info') {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] [${level.toUpperCase()}] ${message}`;
    
    // Console output with colors
    switch(level) {
        case 'error':
            console.error('\x1b[31m%s\x1b[0m', logMessage);
            break;
        case 'warn':
            console.warn('\x1b[33m%s\x1b[0m', logMessage);
            break;
        default:
            console.log('\x1b[36m%s\x1b[0m', logMessage);
    }
    
    // Also log to file
    fs.appendFileSync(actionsLogPath, logMessage + '\n');
}

// Poll for IPs to send
function pollIPQueue() {
    if (fs.existsSync(ipQueuePath)) {
        try {
            const data = fs.readFileSync(ipQueuePath, 'utf8').trim();
            if (!data) return;
            
            const ipList = data.split('\n').filter(ip => ip.trim() !== '');
            if (ipList.length === 0) return;
            
            log(`📤 Sending ${ipList.length} IPs from queue`);
            
            let success = false;
            if (ws.readyState === WebSocket.OPEN) {
                ipList.forEach(ip => {
                    if (isValidIP(ip.trim())) {
                        // Generate a unique requestId for each IP being sent from the queue
                        // This is different from server-generated requestIds but will still work
                        const requestId = generateRequestId();
                        
                        ws.send(JSON.stringify({
                            type: 'BLOCK_IP',
                            client_id: clientId,
                            token: token,
                            ip: ip.trim(),
                            source: 'fail2ban',
                            requestId: requestId,
                            timestamp: new Date().toISOString()
                        }));
                        success = true;
                    } else {
                        log(`[⚠️] Skipping invalid IP in queue: ${ip}`, 'warn');
                    }
                });
                
                if (success) {
                    // Remove queue after successful send
                    fs.unlinkSync(ipQueuePath);
                }
            } else {
                log('[⚠️] Cannot send IPs - disconnected from server', 'warn');
            }
        } catch (e) {
            log(`[❌] Error processing IP queue: ${e.message}`, 'error');
        }
    }
}

// Check queue every 3 seconds
setInterval(pollIPQueue, 3000);

// Start metrics collection
let lastMinuteBlockCount = 0;
let lastHourBlockCount = 0;

// Collect metrics every minute
setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            type: 'METRICS',
            client_id: clientId,
            token: token,
            metrics: {
                lastMinuteBlockCount,
                lastHourBlockCount,
                uptime: process.uptime(),
                memoryUsage: process.memoryUsage(),
                timestamp: new Date().toISOString()
            }
        }));
    }
    
    // Reset minute counter
    lastMinuteBlockCount = 0;
}, 60000);

// Establish initial connection
connect();

// Export for potential use in other modules
module.exports = {
    blockIP,
    unblockIP,
    reportError
};