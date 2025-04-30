
# 🛡️ Adaptive SSH Defense Agents (ASDA)
ASDA adalah sistem terdistribusi untuk mendeteksi, memblokir, dan menyebarkan informasi serangan brute force SSH secara otomatis antar server menggunakan Fail2Ban dan WebSocket.

---

## 📦 Struktur Proyek
```
server/ 
├── server.js 
├── .env 
├── logs/
│ └── server_log.csv

client/ 
├── client.js 
├── .env 
├── block_from_server.sh 
├── unblock_from_server.sh 
├── fail2ban-trigger.sh 
├── .ip_queue 
├── logs/ 
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

Semua komunikasi antara client dan server menggunakan **format JSON** agar seragam, mudah dikelola, dan fleksibel untuk pengembangan lanjutan.

### 🔐 1. Registrasi Client (saat koneksi terbuka)

```json
{
  "type": "REGISTER",
  "client_id": "client-01"
}
```
-   Harus dikirim oleh client segera setelah terkoneksi ke server
-   Server menyimpan `client_id` agar bisa mencatat log dengan nama client
### 🚨 2. Permintaan Pemblokiran IP (dikirim dari client pelapor)

```json
{
  "type": "BLOCK_IP",
  "client_id": "client-01",
  "ip": "192.168.100.123"
}
```
-   Menandakan bahwa client `client-01` mendeteksi IP penyerang
-   Server akan menyebarkan data ini ke seluruh client lain (kecuali pengirim)
-   Semua client yang menerima akan memblokir IP tersebut secara otomatis
---
## 🚀 Status
- Dalam tahap pengembangan awal.
---

Proyek ini dibuat sebagai bagian dari penelitian tugas akhir.

