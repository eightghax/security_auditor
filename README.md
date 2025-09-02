# Security Auditor

Script audit keamanan read-only untuk sistem Linux yang menganalisis aktivitas mencurigakan dalam 24 jam terakhir. Script ini dirancang untuk forensik dan monitoring keamanan tanpa mengubah konfigurasi sistem.

## 📋 Fitur

### Analisis SSH & Authentication
- Login SSH yang gagal dan berhasil (password/publickey)
- Deteksi scanning user invalid
- Analisis IP address penyerang terbanyak
- Monitoring koneksi SSH aktif
- Riwayat login dengan `last` dan `lastb`

### Monitoring Sistem
- Proses mencurigakan (reverse shells, network tools)
- Service yang listening pada port tidak biasa
- Binary sistem yang dimodifikasi dalam 24 jam
- File SUID/SGID yang berubah
- Aktivitas sudo commands

### Deteksi Persistence & Backdoor
- Perubahan file startup (systemd, init.d, rc.local)
- Modifikasi shell profiles (.bashrc, .profile, dll)
- Perubahan authorized_keys dan config SSH
- Modifikasi file sudoers dan cron

### Analisis Log & Integrity
- Deteksi potensi log tampering
- File besar yang dibuat di /tmp, /var/tmp, /dev/shm
- Hidden files di lokasi sistem
- Perubahan package (apt/yum/dnf) dalam 24 jam

### Specific untuk Distro
- **Ubuntu**: Fail2ban, UFW firewall, dpkg logs
- **CentOS/Rocky**: SELinux denials, firewalld, audit logs, RPM changes

## 🚀 Penggunaan

### Ubuntu/Debian
```bash
# Download dan jalankan
chmod +x ubuntu_check.sh
sudo ./ubuntu_check.sh

# Output tersimpan di /tmp/ubuntu_24h_security_audit_YYYYMMDD_HHMMSS.txt
```

### CentOS/Rocky Linux/RHEL
```bash
# Download dan jalankan
chmod +x centos_check.sh
sudo ./centos_check.sh

# Output tersimpan di /tmp/centos_24h_security_audit_YYYYMMDD_HHMMSS.txt
```

## 📝 Output Report

Setiap script menghasilkan laporan lengkap yang mencakup:

### Summary Section
```
===== Summary (last 24h) =====
Failed SSH logins       : 127
Invalid user scans      : 89
Accepted (password)     : 3
Accepted (publickey)    : 12
Active SSH connections  : 2
```

### Detail Analysis
- **Top attacking IPs**: IP address dengan login gagal terbanyak
- **Successful logins**: Detail user@ip yang berhasil login
- **Process monitoring**: Proses yang berpotensi malicious
- **File changes**: File penting yang dimodifikasi
- **Network analysis**: Koneksi jaringan mencurigakan

## 🔒 Keamanan

✅ **READ-ONLY**: Script tidak mengubah konfigurasi sistem  
✅ **Safe to run**: Hanya membaca log dan status  
✅ **No impact**: Tidak mempengaruhi service yang berjalan  
✅ **Forensic ready**: Output dapat digunakan untuk analisis forensik  

## 📊 Contoh Kasus Penggunaan

### 1. Incident Response
```bash
# Setelah menerima alert intrusion detection
sudo ./ubuntu_check.sh
# Analisis laporan untuk menentukan scope serangan
```

### 2. Daily Security Monitoring
```bash
# Cron job harian untuk monitoring rutin
0 1 * * * /path/to/ubuntu_check.sh >/dev/null 2>&1
```

### 3. Compliance Audit
```bash
# Generate laporan untuk audit keamanan bulanan
sudo ./centos_check.sh
# Submit laporan ke security team
```

## 🛠️ Requirements

### Ubuntu/Debian
- `journalctl` (systemd)
- `ss` (network analysis)
- `sudo` privileges untuk log access
- Optional: `fail2ban-client`, `ufw`

### CentOS/Rocky Linux
- `journalctl` (systemd)
- `ss` (network analysis) 
- `sudo` privileges untuk log access
- Optional: `firewall-cmd`, `aureport`, `sealert`

## 📋 Checklist Analisis

Script ini memeriksa indikator compromise berikut:

- [ ] **Brute force attacks**: Login SSH gagal berulang
- [ ] **Successful breaches**: Login yang berhasil dari IP asing
- [ ] **Privilege escalation**: Perubahan SUID/sudo files
- [ ] **Persistence**: Backdoor di startup files
- [ ] **Data exfiltration**: Koneksi keluar mencurigakan
- [ ] **Log tampering**: Modifikasi file log
- [ ] **Malware**: Proses dan binary mencurigakan
- [ ] **Lateral movement**: Koneksi antar-host internal

## 🔍 Interpretasi Output

### Prioritas Tinggi
- Login berhasil dari IP tidak dikenal
- Binary sistem yang dimodifikasi
- File SUID/SGID baru
- Proses reverse shell

### Prioritas Sedang  
- Login gagal berulang dari IP sama
- Perubahan authorized_keys
- Hidden files di lokasi sistem
- Service pada port tidak biasa

### Prioritas Rendah
- Scanning user invalid (normal pada internet)
- Log rotasi normal
- Update package legitimate

## 📚 References

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS Linux Forensics](https://www.sans.org/white-papers/1040/)
- [CIS Controls](https://www.cisecurity.org/controls/)

## 🤝 Kontribusi

Kontribusi dalam bentuk:
- Penambahan deteksi baru
- Optimasi performa
- Support distro Linux lain
- Perbaikan bug

## 📄 License

MIT License - Bebas digunakan untuk tujuan komersial dan non-komersial.

---

**⚠️ Disclaimer**: Script ini untuk tujuan audit dan monitoring keamanan. Penggunaan untuk aktivitas ilegal tidak dianjurkan dan menjadi tanggung jawab pengguna.
