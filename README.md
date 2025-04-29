# Adaptive SSH Defense Agents (ASDA)
ASDA adalah sistem terdistribusi yang dirancang untuk mendeteksi, memblokir, dan menyebarkan informasi serangan brute force SSH secara real-time menggunakan Fail2Ban dan WebSocket.

## 📁 Struktur Direktori

### server/
- `server.js`: WebSocket Server untuk menerima dan mendistribusikan IP.
- `config/clients.json`: Daftar IP client ASDA.
- `logs/received_ips.log`: Log IP yang diterima dan disebarkan.

### client/
- `client.js`: WebSocket Client untuk mengirim dan menerima IP.
- `fail2ban-trigger.sh`: Dipanggil oleh Fail2Ban saat IP diblokir.
- `block_from_server.sh`: Eksekusi pemblokiran IP yang diterima dari server.
- `config/server.json`: Konfigurasi IP dan port WebSocket Server.
- `logs/actions.log`: Log semua aksi pemblokiran di sisi client.

## 🛠️ Teknologi
- **Fail2Ban** untuk deteksi brute force SSH
- **Node.js** + `ws` library untuk komunikasi real-time WebSocket
- **iptables** / perintah sistem untuk pemblokiran IP

## 🚀 Status
Proyek dalam tahap pengembangan awal.
