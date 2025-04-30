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

        try {
            const data = JSON.parse(message);
            const clientId = data.client_id || clientMap.get(ws) || 'unknown';

            if (!validateMessage(data)) {
                console.warn(`[⚠️] Pesan dari ${clientId} tidak valid: `, data);
                return; // langsung abaikan
            }

            // Proses REGISTER
            if (data.type === 'REGISTER') {
                clientMap.set(ws, clientId);
                console.log(`🆔 Client registered: ${clientId}`);
                return;
            }

            // Proses BLOCK_IP
            if (data.type === 'BLOCK_IP') {
                const payload = JSON.stringify(data);
                let forwardedCount = 0;

                wss.clients.forEach(client => {
                    if (client !== ws && client.readyState === WebSocket.OPEN) {
                        client.send(payload);
                        forwardedCount++;
                    }
                });

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

function validateMessage(data) {
    // Validasi struktur pesan
    if (!data || typeof data !== 'object') return false;
    // Cek apakah ada field yang diperlukan
    if (!data.type || !data.client_id) return false;
    // Cek token cocok dengan token server
    if (data.token !== process.env.SECRET_TOKEN) return false;

    // Cek apakah type valid
    if (data.type === 'BLOCK_IP') {
        // Validasi IP address sederhana (IPv4)
        const ipRegex = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
        if (!data.ip || !ipRegex.test(data.ip)) return false;
    }

    return true;
}