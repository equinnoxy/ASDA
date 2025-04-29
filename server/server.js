require('dotenv').config();
const WebSocket = require('ws');

const port = process.env.PORT || 3000;
const wss = new WebSocket.Server({ port });

console.log(`🔌 ASDA WebSocket Server running on port ${port}`);

wss.on('connection', (ws, req) => {
    console.log('✅ New client connected:', req.socket.remoteAddress);

    ws.on('message', (message) => {
        console.log('📩 Message received:', message.toString());

        // Broadcast to all clients except sender
        wss.clients.forEach(client => {
            if (client !== ws && client.readyState === WebSocket.OPEN) {
                client.send(message.toString());
            }
        });
    });

    ws.on('close', () => {
        console.log('❌ Client disconnected');
    });
});
