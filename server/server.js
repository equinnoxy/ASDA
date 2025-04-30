require('dotenv').config();
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');

const port = process.env.PORT || 3000;
const logPath = path.join(__dirname, 'logs', 'server_log.csv');

const wss = new WebSocket.Server({ port });
const clientMap = new Map(); // ws => client_id
console.log(`🔌 ASDA WebSocket Server running on port ${port}`);

// Tulis header kalau file belum ada
if (!fs.existsSync(logPath)) {
    fs.writeFileSync(logPath, 'timestamp,source_ip,forwarded_to,total_clients,message\n');
}

wss.on('connection', (ws, req) => {
    const clientIp = req.socket.remoteAddress;
    console.log(`✅ Client connected: ${clientIp}`);

    ws.on('message', (message) => {
        const timestamp = new Date().toISOString();
        const totalClients = wss.clients.size;
        let forwardedCount = 0;

        try {
            const data = JSON.parse(message);
            const clientId = data.client_id || clientMap.get(ws) || 'unknown';

            // Register client ID
            if (data.type === 'REGISTER' && data.client_id) {
                clientMap.set(ws, data.client_id);
                console.log(`🆔 Client registered: ${data.client_id}`);
                return;
            }

            // Pemblokiran IP
            if (data.type === 'BLOCK_IP' && data.ip) {
                const payload = JSON.stringify(data);

                wss.clients.forEach(client => {
                    if (client !== ws && client.readyState === WebSocket.OPEN) {
                        client.send(payload);
                        forwardedCount++;
                    }
                });

                // Logging
                const logLine = `${timestamp},${clientId},${forwardedCount},${totalClients},${data.type}:${data.ip}\n`;
                fs.appendFileSync(logPath, logLine);

                console.log(`📩 BLOCK_IP from ${clientId} forwarded to ${forwardedCount}/${totalClients}`);
            }
        } catch (e) {
            console.error(`[❌] Gagal parse JSON dari client:`, e.message);
        }
    });

    ws.on('close', () => {
        console.log(`❌ Client disconnected: ${clientIp}`);
    });
});
