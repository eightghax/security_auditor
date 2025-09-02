#!/usr/bin/env bash
# Ubuntu 24h Security Check (read-only)
# Output: /tmp/ubuntu_24h_security_audit_<timestamp>.txt

set -Eeuo pipefail

SINCE_HUMAN="24 hours ago"
SINCE_ISO="$(date -d "$SINCE_HUMAN" '+%Y-%m-%d %H:%M:%S %z')"
NOW_ISO="$(date '+%Y-%m-%d %H:%M:%S %z')"
TS="$(date '+%Y%m%d_%H%M%S')"
REPORT="/tmp/ubuntu_24h_security_audit_${TS}.txt"

SUDO=""
if [[ $EUID -ne 0 ]]; then SUDO="sudo"; fi

log() { printf "%s\n" "$*" | tee -a "$REPORT" >/dev/null; }
hdr() { printf "\n===== %s =====\n" "$1" | tee -a "$REPORT" >/dev/null; }
cmd() {
  echo "\$ $*" | tee -a "$REPORT" >/dev/null
  eval "$*" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tee -a "$REPORT" >/dev/null || true
  echo | tee -a "$REPORT" >/dev/null
}

# Prefer journalctl (waktu bisa difilter) + fallback auth.log bila perlu
JCTL="journalctl --no-pager --since \"$SINCE_HUMAN\" --until now"
JCTL_SSH="$SUDO bash -c '$JCTL SYSLOG_IDENTIFIER=sshd'"
JCTL_SUDO="$SUDO bash -c '$JCTL SYSLOG_IDENTIFIER=sudo'"
JCTL_AUTH="$SUDO bash -c '$JCTL -t sshd -t sudo -t ssh'"

# KALKULASI RINGKAS (pakai journalctl; jika kosong, fallback grep auth.log)
extract_or_fallback() {
  local pattern="$1"
  local out
  out=$(eval "$JCTL_SSH" | grep -F "$pattern" || true)
  if [[ -z "$out" ]]; then
    # fallback ke auth.log*/compressed (tanpa filter waktu yang presisi)
    out=$( ( $SUDO zgrep -h "$pattern" /var/log/auth.log* 2>/dev/null || true ) )
  fi
  printf "%s" "$out"
}

FAILED_ALL="$(extract_or_fallback 'Failed password')"
INVALID_ALL="$(extract_or_fallback 'Invalid user')"
ACCEPTED_PASS_ALL="$(extract_or_fallback 'Accepted password')"
ACCEPTED_PKEY_ALL="$(extract_or_fallback 'Accepted publickey')"

FAILED_CNT="$(printf "%s" "$FAILED_ALL" | grep -c . || true)"
INVALID_CNT="$(printf "%s" "$INVALID_ALL" | grep -c . || true)"
ACCPASS_CNT="$(printf "%s" "$ACCEPTED_PASS_ALL" | grep -c . || true)"
ACCPKEY_CNT="$(printf "%s" "$ACCEPTED_PKEY_ALL" | grep -c . || true)"

ACTIVE_SSH_CONN="$($SUDO ss -Htan state established '( sport = :22 )' 2>/dev/null | wc -l || echo 0)"

# HEADER
: > "$REPORT"
hdr "Ubuntu 24h Security Check (READ-ONLY)"
log "Host        : $(hostname -f 2>/dev/null || hostname)"
log "Time Window : $SINCE_ISO  →  $NOW_ISO"
log "Timezone    : $(date +%Z) ($(date +%z))"
log "User        : $(whoami) (need sudo for full results: $([[ -z $SUDO ]] && echo yes || echo no))"
log ""

# SUMMARY
hdr "Summary (last 24h)"
log "Failed SSH logins       : $FAILED_CNT"
log "Invalid user scans      : $INVALID_CNT"
log "Accepted (password)     : $ACCPASS_CNT"
log "Accepted (publickey)    : $ACCPKEY_CNT"
log "Active SSH connections  : $ACTIVE_SSH_CONN"
log ""

# TOP ATTACKING IPs
hdr "Top source IPs for failed logins"
if [[ -n "$FAILED_ALL" ]]; then
  printf "%s" "$FAILED_ALL" \
    | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' \
    | sort | uniq -c | sort -nr | head -n 20 | tee -a "$REPORT" >/dev/null
else
  log "(no data)"
fi

hdr "Top source IPs for invalid users"
if [[ -n "$INVALID_ALL" ]]; then
  printf "%s" "$INVALID_ALL" \
    | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' \
    | sort | uniq -c | sort -nr | head -n 20 | tee -a "$REPORT" >/dev/null
else
  log "(no data)"
fi

# ACCEPTED SESSIONS DETAIL
hdr "Successful SSH logins (user@ip)"
{
  printf "%s\n" "$ACCEPTED_PASS_ALL"
  printf "%s\n" "$ACCEPTED_PKEY_ALL"
} | awk '
  /Accepted (password|publickey)/ {
    user=""; ip="";
    for(i=1;i<=NF;i++){
      if($i=="for"){user=$(i+1)}
      if($i=="from"){ip=$(i+1)}
    }
    if(user!="" && ip!=""){print user"@"ip}
  }' | sort | uniq -c | sort -nr | tee -a "$REPORT" >/dev/null

# REALTIME & HISTORY SNAPSHOTS
hdr "Who is logged in now"
cmd "$SUDO w"
cmd "$SUDO who"

hdr "Established SSH connections (server port 22)"
cmd "$SUDO ss -ntp state established '( sport = :22 )'"

hdr "SSH Service status & logs (last 24h)"
cmd "$SUDO systemctl status ssh --no-pager"
cmd "$SUDO bash -c '$JCTL_AUTH | tail -n 400'"

hdr "Auth log highlights (last 24h; sshd & sudo)"
cmd "$SUDO bash -c '$JCTL -t sshd -t sudo | grep -E \"Failed password|Invalid user|Accepted|sudo|COMMAND\" || true'"

# SUDO COMMANDS
hdr "Commands executed via sudo (last 24h)"
cmd "$SUDO bash -c '$JCTL_SUDO | grep -F COMMAND= || true'"

# FAILED & SUCCESS HISTORY
hdr "Login history (last 24h)"
cmd "$SUDO last -s -24hours"
hdr "Failed login attempts (last 24h)"
cmd "$SUDO lastb -s -24hours || true"

# NETWORK OVERVIEW
hdr "Listening ports (all)"
cmd "$SUDO ss -tulpn"

hdr "Established NON-SSH connections (possible outbound/inbound services)"
cmd "$SUDO ss -ntp state established | grep -v \":22 \" || true"

# FILE/CONFIG CHANGES (last 24h)
hdr "Recent changes: SSH config files (/etc/ssh) in last 24h"
cmd "$SUDO find /etc/ssh -type f -newermt '$SINCE_HUMAN' -printf '%TY-%Tm-%Td %TH:%TM  %u:%g  %p\n'"

hdr "Recent changes: authorized_keys (root & users) in last 24h"
cmd "$SUDO bash -c 'find /root /home -maxdepth 3 -path \"*/.ssh/authorized_keys\" -newermt \"$SINCE_HUMAN\" -printf \"%TY-%Tm-%Td %TH:%TM  %u:%g  %p\n\" 2>/dev/null'"

hdr "Recent changes: sudoers in last 24h"
cmd "$SUDO bash -c 'find /etc/sudoers /etc/sudoers.d -type f -newermt \"$SINCE_HUMAN\" -printf \"%TY-%Tm-%Td %TH:%TM  %u:%g  %p\n\" 2>/dev/null'"

hdr "Recent changes: cron & timers in last 24h"
cmd "$SUDO bash -c 'find /etc/cron* /var/spool/cron/crontabs -type f -newermt \"$SINCE_HUMAN\" -printf \"%TY-%Tm-%Td %TH:%TM  %u:%g  %p\n\" 2>/dev/null'"
cmd "systemctl list-timers --all"

# OPTIONAL TOOLS (status only, jika ada)
if command -v ufw >/dev/null 2>&1; then
  hdr "UFW firewall status"
  cmd "$SUDO ufw status verbose || true"
fi

if command -v fail2ban-client >/dev/null 2>&1; then
  hdr "Fail2Ban status (global & sshd)"
  cmd "$SUDO fail2ban-client status || true"
  cmd "$SUDO fail2ban-client status sshd || true"
  hdr "Fail2Ban recent Ban/Unban (tail)"
  cmd "$SUDO bash -c 'tail -n 300 /var/log/fail2ban.log 2>/dev/null | grep -E \"Ban|Unban\" || true'"
fi

# PACKAGE / BINARY CHANGES (indikasi modifikasi sistem)
if [[ -f /var/log/dpkg.log ]]; then
  hdr "APT/dpkg activity (last 24h)"
  cmd "$SUDO awk -v ts=\"$(date -d \"$SINCE_HUMAN\" +%Y-%m-%d\\ %H:%M:%S)\" '(\$1\" \"\$2)>=ts {print}' /var/log/dpkg.log || true"
fi

# USERS & GROUPS SNAPSHOT
hdr "Human users & sudo group members (snapshot)"
cmd "$SUDO awk -F: '\$3>=1000 && \$1!=\"nobody\"{print \$1\":\"\$7}' /etc/passwd"
cmd "$SUDO getent group sudo"

# PROCESS MONITORING (mencurigakan)
hdr "Suspicious processes (reverse shells, network tools, unusual binaries)"
cmd "ps auxww | grep -E '(nc|netcat|socat|ncat|bash.*-i|sh.*-i|python.*socket|perl.*socket|ruby.*socket|telnet.*[0-9]|wget.*sh|curl.*sh)' | grep -v grep || echo 'None found'"

hdr "Processes listening on unusual ports (not 22,80,443,53)"
cmd "$SUDO ss -tulpn | awk '\$1~/tcp|udp/ && \$5!~/:(22|80|443|53|25|110|143|993|995|587|465)\$/ {print}' | head -20"

# SYSTEM INTEGRITY CHECKS
hdr "Recently modified binaries in system paths (last 24h)"
cmd "$SUDO find /usr/bin /usr/sbin /bin /sbin -type f -newermt '$SINCE_HUMAN' -printf '%TY-%Tm-%Td %TH:%TM  %u:%g  %s  %p\n' 2>/dev/null || echo 'None found'"

hdr "SUID/SGID files modified in last 24h"
cmd "$SUDO find / -type f \\( -perm -4000 -o -perm -2000 \\) -newermt '$SINCE_HUMAN' -printf '%TY-%Tm-%Td %TH:%TM  %m  %u:%g  %p\n' 2>/dev/null | head -20 || echo 'None found'"

# LOG TAMPERING DETECTION
hdr "Log file modifications (potential tampering in last 24h)"
cmd "$SUDO find /var/log -name '*.log*' -newermt '$SINCE_HUMAN' -printf '%TY-%Tm-%Td %TH:%TM  %s  %p\n' 2>/dev/null | head -20"

# PERSISTENCE MECHANISMS
hdr "Recently modified startup files (systemd, init.d, rc.local)"
cmd "$SUDO bash -c 'find /etc/systemd/system /etc/init.d /etc/rc*.d /etc/rc.local -type f -newermt \"$SINCE_HUMAN\" -printf \"%TY-%Tm-%Td %TH:%TM  %u:%g  %p\n\" 2>/dev/null'"

hdr "User shell profiles modified in last 24h"
cmd "$SUDO bash -c 'find /root /home -maxdepth 2 -name \".*profile\" -o -name \".*bashrc\" -o -name \".*bash_profile\" -o -name \".*zshrc\" | xargs ls -la --time-style=long-iso 2>/dev/null | awk -v since=\"$(date -d \"$SINCE_HUMAN\" +%Y-%m-%d)\" \"\$6>=since {print}\"'"

# KERNEL & HARDWARE EVENTS
hdr "Kernel messages & hardware events (last 24h)"
cmd "$SUDO bash -c '$JCTL -k | grep -E \"USB|usb|inserted|removed|mounted|umount|segfault|killed|OOM\" | tail -20 || true'"

# UNUSUAL NETWORK ACTIVITY
hdr "Outbound connections to suspicious ports (not web/mail/dns)"
cmd "$SUDO ss -ntp state established | awk '\$4!~/:(22|80|443|53|25|110|143|993|995|587|465)\$/ && \$5!~/:(22|80|443|53|25|110|143|993|995|587|465)\$/ {print}' | head -20"

# FILE SYSTEM ANOMALIES
hdr "Large files created in /tmp, /var/tmp, /dev/shm (last 24h)"
cmd "$SUDO find /tmp /var/tmp /dev/shm -type f -newermt '$SINCE_HUMAN' -size +1M -printf '%TY-%Tm-%Td %TH:%TM  %s  %u:%g  %p\n' 2>/dev/null || echo 'None found'"

hdr "Hidden files/directories created in system locations (last 24h)"
cmd "$SUDO find /etc /usr /var -name '.*' -newermt '$SINCE_HUMAN' -printf '%TY-%Tm-%Td %TH:%TM  %u:%g  %p\n' 2>/dev/null | head -20 || echo 'None found'"

hdr "END OF REPORT"
log ""
log "Saved report to: $REPORT"
