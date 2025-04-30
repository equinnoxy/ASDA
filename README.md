
# 🛡️ Adaptive SSH Defense Agents (ASDA)
ASDA adalah sistem terdistribusi untuk mendeteksi, memblokir, dan menyebarkan informasi serangan brute force SSH secara otomatis antar server menggunakan Fail2Ban dan WebSocket.

---

## 📦 Struktur Proyek
```
server/ 
├── server.js 
├── .env 
├── config/ 
├── logs/

client/ 
├── client.js 
├── .env 
├── block_from_server.sh 
├── unblock_from_server.sh 
├── fail2ban-trigger.sh 
├── .ip_queue 
├── logs/ 
│ ├── actions.log 
│ └── block_log.csv
```

---

## ⚙️ Teknologi & Dependensi

- Node.js (v18+)
- Fail2Ban (aktif pada jail `sshd`)
- WebSocket (`ws` package)
- atd (untuk penjadwalan unban otomatis)
- Ubuntu/Debian-based system

---

## 📜 Cara Kerja Sistem

1. **Deteksi**: Fail2Ban mendeteksi brute force SSH.
2. **Trigger**: `fail2ban-trigger.sh` dipanggil → IP dimasukkan ke `.ip_queue`.
3. **Distribusi**: `client.js` membaca antrean → kirim IP ke WebSocket Server.
4. **Broadcast**: `server.js` menyebarkan IP ke semua client lain.
5. **Blokir**: Semua client lain memanggil `block_from_server.sh` → Fail2Ban blokir IP.
6. **Unban Otomatis**: `unblock_from_server.sh` dijalankan oleh `at` setelah 120 detik.

---

## 📌 Log & Visualisasi

- Semua pemblokiran dan unban pada client tercatat di `logs/block_log.csv` dalam format:
```
timestamp,ip,action 
2025-04-29 20:31:11,192.168.1.101,BLOCK 
2025-04-29 20:33:11,192.168.1.101,UNBLOCK
```
- Sedangkan untuk server tercatat di `logs/server_log.csv` dalam format:
```
timestamp,source_id,forwarded_to,total_clients,message
2025-04-29T18:30:22.153Z,client-01,2,3,BLOCK_IP:192.168.100.123"
```
- File ini dapat digunakan untuk visualisasi serangan atau analisis keamanan.

---

## 🛠️ Setup Awal

### 1. Install Dependensi:
```bash
sudo apt update
sudo apt install fail2ban at
# Di client/ dan server/
npm install
```
### 2. Aktifkan atd Service:
```bash
sudo systemctl enable --now atd
```
### 3. Beri Izin Eksekusi:
```bash
chmod +x *.sh
```
### 4. Jalankan Server & Client:
```bash
# Di server/
node server.js

# Di client/
node client.js
```
---
## 📋 Catatan Tambahan
-   Jika menggunakan `sudo`, pastikan permission script benar atau dijalankan dari user yang diizinkan.
-   Pastikan semua client aktif saat server melakukan broadcast.
---
## 📡 Format Pesan WebSocket

Semua komunikasi antara client dan server menggunakan **format JSON** agar seragam, mudah dikelola, dan aman untuk parsing serta logging.

### 🔐 1. Registrasi Client (saat koneksi terbuka)

```json
{
  "type": "REGISTER",
  "client_id": "client-01",
  "token": "ASDA_SECRET_2025"
}
```
-   Dikirim sekali saat client terkoneksi ke server.
-   Wajib berisi `client_id` dan `token`.
### 🚨 2. Permintaan Pemblokiran IP (dikirim dari client pelapor)

```json
{
  "type": "BLOCK_IP",
  "client_id": "client-01",
  "ip": "192.168.100.123",
  "token": "ASDA_SECRET_2025"
}
```
-   Dikirim oleh client pelapor ke server.
-   Server akan memvalidasi, lalu menyebarkannya ke semua client lain.
-   Client penerima akan memanggil `block_from_server.sh <IP>`.
---
## 🛡️ Sistem Autentikasi
-   Semua pesan harus menyertakan **token rahasia** (`token`) yang diset di `.env`.
-   Server memverifikasi token sebelum memproses pesan.
-   Pesan yang tidak memiliki token valid **akan diabaikan secara otomatis**.

📁 Contoh `.env` di Server
```env
PORT=3000
SECRET_TOKEN=ASDA_SECRET_2025
```
📁 Contoh `.env` di Client
```env
SERVER_IP=127.0.0.1
SERVER_PORT=3000
CLIENT_ID=client-01
SECRET_TOKEN=ASDA_SECRET_2025
```

Pesan hanya akan diproses jika:
-   Format JSON valid
-   `type`, `client_id`, dan `token` tersedia
-   `ip` valid (untuk `BLOCK_IP`)
-   Token cocok dengan token milik server (`process.env.SECRET_TOKEN`)
---
## 🚀 Status
- Dalam tahap pengembangan awal.
---

Proyek ini dibuat sebagai bagian dari penelitian tugas akhir.

