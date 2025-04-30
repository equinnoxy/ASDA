require('dotenv').config();
const WebSocket = require('ws');
const { exec } = require('child_process');
const fs = require('fs');

const serverIp = process.env.SERVER_IP;
const serverPort = process.env.SERVER_PORT;
const clientId = process.env.CLIENT_ID;
const token = process.env.SECRET_TOKEN;
const url = `ws://${serverIp}:${serverPort}`;
const path = '.ip_queue';

const ws = new WebSocket(url);

ws.on('open', () => {
    console.log(`✅ Connected to ASDA WebSocket Server at ${url}`);

    ws.send(JSON.stringify({
        type: 'REGISTER',
        client_id: clientId,
        token: token // Ganti dengan ID unik untuk setiap client
    }));
});

ws.on('message', (message) => {
    try {
        const data = JSON.parse(message);
        if (data.type === 'BLOCK_IP' && data.ip) {
            const ip = data.ip;
            console.log(`🔒 Memblokir IP: ${ip}`);
            exec(`./block_from_server.sh ${ip}`, (err, stdout, stderr) => {
                if (err) {
                    console.error(`[❌] Gagal eksekusi blokir IP: ${stderr}`);
                    return;
                }
                console.log(stdout);
            });
        } else {
            console.warn(`[⚠️] Pesan diterima tapi tidak diproses:`, data);
        }
    } catch (e) {
        console.error(`[❌] Gagal parsing pesan:`, e.message);
    }
});

ws.on('close', () => {
    console.log('❌ Disconnected from server');
});

// Fungsi polling file .ip_to_send
setInterval(() => {
    if (fs.existsSync(path)) {
        const data = fs.readFileSync(path, 'utf8').trim();
        const ipList = data.split('\n').filter(ip => ip !== '');

        ipList.forEach(ip => {
            console.log(`📤 Mengirim IP dari antrean: ${ip}`);
            ws.send(JSON.stringify({
                type: 'BLOCK_IP',
                client_id: clientId,
                token: token,
                ip: ip
            }));
        });

        fs.unlinkSync(path); // hapus antrean setelah dikirim semua
    }
}, 3000); // polling setiap 3 detik