require('dotenv').config();
const WebSocket = require('ws');
const { exec } = require('child_process');
const fs = require('fs');

const serverIp = process.env.SERVER_IP;
const serverPort = process.env.SERVER_PORT;
const url = `ws://${serverIp}:${serverPort}`;

const ws = new WebSocket(url);

ws.on('open', () => {
    console.log('✅ Connected to ASDA WebSocket Server');

    // Dummy message kirim IP dari client sendiri
    const dummyIP = '192.168.100.123';
    ws.send(`BLOCK_IP:${dummyIP}`);
});

ws.on('message', (message) => {
    console.log('📥 Received from server:', message.toString());

    const [action, ip] = message.toString().split(':');

    if (action === 'BLOCK_IP' && ip) {
        console.log(`🔒 Memproses pemblokiran IP ${ip}...`);

        // Panggil shell script block_from_server.sh
        exec(`./block_from_server.sh ${ip}`, (err, stdout, stderr) => {
            if (err) {
                console.error(`[❌] Gagal eksekusi blokir IP: ${stderr}`);
                return;
            }
            console.log(stdout);
        });
    }
});

ws.on('close', () => {
    console.log('❌ Disconnected from server');
});

// Fungsi polling file .ip_to_send
setInterval(() => {
  if (fs.existsSync('.ip_to_send')) {
    const ip = fs.readFileSync('.ip_to_send', 'utf8').trim();
    if (ip) {
      console.log(`📤 Mengirim IP dari Fail2Ban: ${ip}`);
      ws.send(`BLOCK_IP:${ip}`);
    }
    fs.unlinkSync('.ip_to_send'); // hapus setelah dikirim
  }
}, 3000); // tiap 3 detik

