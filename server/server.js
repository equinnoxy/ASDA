require('dotenv').config();
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');

const port = process.env.PORT || 3000;
const logPath = path.join(__dirname, 'logs', 'server_log.csv');

const wss = new WebSocket.Server({ port });
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

        // Kirim ke semua client kecuali pengirim
        wss.clients.forEach(client => {
            if (client !== ws && client.readyState === WebSocket.OPEN) {
                client.send(message.toString());
                forwardedCount++;
            }
        });

        const logLine = `${timestamp},${clientIp},${forwardedCount},${totalClients},"${message.toString()}"\n`;
        fs.appendFileSync(logPath, logLine);

        console.log(`📩 Message from ${clientIp} forwarded to ${forwardedCount}/${totalClients} clients`);
    });

    ws.on('close', () => {
        console.log(`❌ Client disconnected: ${clientIp}`);
    });
});
