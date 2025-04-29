#!/bin/bash

# --------------------------------------------
# Script ini dipanggil otomatis oleh Fail2Ban
# saat sebuah IP diblokir oleh jail sshd
# --------------------------------------------
# Argumen 1: IP address penyerang
# --------------------------------------------

IP="$1"

if [ -z "$IP" ]; then
  echo "[❌] Tidak ada IP yang diberikan ke trigger."
  exit 1
fi

# Kirim IP ke client.js (pakai file queue/temp misalnya)
echo "$IP" > .ip_to_send
echo "[INFO] IP $IP dikirim ke client.js melalui .ip_to_send"
