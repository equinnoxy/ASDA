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

# Tambahkan ke file antrian
echo "$IP" >> .ip_queue
echo "[INFO] IP $IP dimasukkan ke antrean .ip_queue"
