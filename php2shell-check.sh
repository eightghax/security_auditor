#!/usr/bin/env bash
# =============================================================================
#  php2shell-check.sh — triage READ-ONLY untuk PHP2Shell
#  (CVE-2026-109618 & CVE-2026-109619)
#
#  Script ini TIDAK mengubah apa pun di server/container: hanya membaca versi
#  PHP, log, file, proses, koneksi, dan konfigurasi container, lalu menulis
#  laporan teks.
#
#  Pakai:
#    sudo ./php2shell-check.sh                     # mode wizard (interaktif)
#    sudo ./php2shell-check.sh -y -m docker -c all # non-interaktif
#    ./php2shell-check.sh -h                       # bantuan
#
#  Exit code: 0 = tidak ada temuan, 1 = ada temuan MED, 2 = ada temuan HIGH
#
#  CATATAN: "tidak ada temuan" BUKAN jaminan bersih. Tetap patch PHP dan
#  rotasi secret penting kalau server sempat rentan dan terekspos internet.
# =============================================================================
set -uo pipefail

VER="1.0"
SINCE_DEFAULT="2026-10-19"
PATCH_DATE="2026-10-21"
declare -A FIXED=( [8.5]=8.5.12 [8.4]=8.4.27 [8.3]=8.3.36 [8.2]=8.2.35 )

# ---------- tampilan ----------
if [[ -t 1 ]]; then
  R=$'\e[31m'; Y=$'\e[33m'; G=$'\e[32m'; B=$'\e[34m'; C=$'\e[36m'; BD=$'\e[1m'; N=$'\e[0m'
else
  R=""; Y=""; G=""; B=""; C=""; BD=""; N=""
fi

REPORT=""
NH=0; NM=0
HIGHS=(); MEDS=()
TGT="host"; TGT_LABEL="host"

_strip() { sed 's/\x1b\[[0-9;]*m//g'; }
log()     { printf '%s\n' "$*"; [[ -n $REPORT ]] && printf '%s\n' "$*" | _strip >>"$REPORT"; return 0; }
section() { log ""; log "${B}${BD}── $* ${N}"; }
high()    { NH=$((NH+1)); HIGHS+=("[$TGT_LABEL] $*"); log "  ${R}${BD}[HIGH]${N} $*"; }
med()     { NM=$((NM+1)); MEDS+=("[$TGT_LABEL] $*");  log "  ${Y}[MED ]${N} $*"; }
info()    { log "  ${C}[INFO]${N} $*"; }
ok()      { log "  ${G}[ OK ]${N} $*"; }
die()     { printf '%s\n' "${R}ERROR:${N} $*" >&2; exit 3; }

# Tampilkan blok teks: terpotong di terminal, lengkap di laporan.
block() {
  local text=$1 max=${2:-15} total
  text=$(printf '%s\n' "$text" | sed '/^[[:space:]]*$/d')
  [[ -z $text ]] && return 0
  total=$(printf '%s\n' "$text" | wc -l)
  printf '%s\n' "$text" | head -n "$max" | cut -c1-220 | sed 's/^/      /'
  (( total > max )) && printf '      %s\n' "... (+$((total-max)) baris lagi, lengkap di laporan)"
  [[ -n $REPORT ]] && printf '%s\n' "$text" | sed 's/^/      /' >>"$REPORT"
  return 0
}
count_lines() { printf '%s\n' "$1" | sed '/^[[:space:]]*$/d' | wc -l; }
ver_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" == "$2" ]]; }  # $1 >= $2

# ---------- eksekusi di target (host / container) ----------
# Variabel yang diteruskan ke target: T_WEB, T_DAYS, T_PAT, T_EXCL
run_t() {
  if [[ $TGT == host ]]; then
    T_WEB="$CUR_WEB" T_DAYS="$DAYS" T_PAT="${T_PAT:-}" T_EXCL="$EXCL_VENDOR" sh -c "$1" 2>/dev/null
  else
    docker exec -e T_WEB="$CUR_WEB" -e T_DAYS="$DAYS" -e T_PAT="${T_PAT:-}" -e T_EXCL="$EXCL_VENDOR" \
      "$TGT" sh -c "$1" 2>/dev/null
  fi
}

# Helper shell yang dipakai di target: find di semua webroot, skip node_modules/.git(/vendor)
T_LIB='
wfind() {
  for w in $T_WEB; do
    [ -d "$w" ] || continue
    if [ "$T_EXCL" = 1 ]; then
      find "$w" \( -path "*/node_modules" -o -path "*/.git" -o -path "*/vendor" \) -prune -o "$@"
    else
      find "$w" \( -path "*/node_modules" -o -path "*/.git" \) -prune -o "$@"
    fi
  done 2>/dev/null
}
'

# =============================================================================
#  CHECKS
# =============================================================================

check_php_version() {
  section "1. Versi PHP"
  local out
  out=$(run_t '
    for b in $(command -v php) /usr/sbin/php-fpm* /usr/local/sbin/php-fpm /usr/bin/php[0-9]* /usr/local/bin/php /usr/local/bin/frankenphp /usr/bin/lsphp /usr/local/lsws/lsphp*/bin/lsphp; do
      [ -x "$b" ] || continue
      v=$("$b" -v 2>/dev/null | grep -oE "PHP [0-9]+\.[0-9]+\.[0-9]+[^ ]*" | head -n1 | cut -d" " -f2)
      [ -n "$v" ] || continue
      rb=$(readlink -f "$b" 2>/dev/null || echo "$b"); pv=""
      if command -v dpkg >/dev/null 2>&1; then
        pkg=$(dpkg -S "$rb" 2>/dev/null | head -n1 | cut -d: -f1)
        [ -n "$pkg" ] && pv="$pkg $(dpkg-query -W -f="\${Version}" "$pkg" 2>/dev/null)"
      fi
      if [ -z "$pv" ] && command -v rpm >/dev/null 2>&1; then
        pv=$(rpm -qf "$rb" 2>/dev/null | grep -v "not owned" | head -n1)
      fi
      echo "$b|$v|$pv"
    done' | sort -u)

  if [[ -z $out ]]; then
    info "Binary PHP tidak ditemukan di target ini."
    return
  fi

  local bin ver pkgv base extra mm fixed
  while IFS='|' read -r bin ver pkgv; do
    [[ -z $bin ]] && continue
    base=$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' <<<"$ver")
    extra=${ver#"$base"}
    [[ -n $pkgv ]] && { extra="${extra:-distro}"; ver="$ver (paket: $pkgv)"; }
    mm=${base%.*}
    fixed=${FIXED[$mm]:-}
    if [[ -n $fixed ]]; then
      if ver_ge "$base" "$fixed"; then
        ok "$bin → PHP $ver (sudah ≥ $fixed)"
      elif [[ -n $extra ]]; then
        med "$bin → PHP $ver: build distro, versi upstream < $fixed. Distro bisa backport patch tanpa menaikkan versi; cek changelog paket (apt changelog / rpm -q --changelog) untuk CVE-2026-109618/109619."
      else
        high "$bin → PHP $ver RENTAN (perlu ≥ $fixed)"
      fi
    elif ver_ge "$base" "8.6.0"; then
      info "$bin → PHP $ver (lebih baru dari tabel; cek advisory manual)"
    else
      if [[ -n $extra ]]; then
        med "$bin → PHP $ver: branch EOL upstream. Cek apakah distro/vendor LTS sudah backport patch."
      else
        high "$bin → PHP $ver: branch EOL & rentan. Upgrade ke 8.2+ (8.2.35/8.3.36/8.4.27/8.5.12) atau pakai backport."
      fi
    fi
  done <<<"$out"
}

check_error_logs() {
  section "2. Log error: memory exhausted / crash worker"
  local pat='Allowed memory size|memory exhausted|Out of memory|zend_mm_heap corrupted|segfault|SIGSEGV|exited on signal (6|7|11)|core dumped|general protection'
  local hits="" f
  if [[ $TGT == host ]]; then
    for f in /var/log/php*fpm*.log* /var/log/php-fpm/*.log* /var/log/nginx/*error*.log* /var/log/apache2/*error*.log* /var/log/httpd/*error_log* /usr/local/lsws/logs/*error*; do
      [[ -f $f && ! -L $f ]] || continue
      if [[ $f == *.gz ]]; then hits+=$(zgrep -EH "$pat" "$f" 2>/dev/null)$'\n'
      else hits+=$(grep -EH "$pat" "$f" 2>/dev/null)$'\n'; fi
    done
    if command -v journalctl >/dev/null 2>&1; then
      hits+=$(journalctl --since "$SINCE" --no-pager -q 2>/dev/null | grep -Ei 'php.*(segfault|general protection|SIGSEGV)|php-fpm.*exited on signal')$'\n'
    fi
  else
    hits=$(docker logs --since "$SINCE" "$TGT" 2>&1 | grep -E "$pat")$'\n'
    hits+=$(T_PAT="$pat" run_t 'for f in /var/log/php*fpm*.log /var/log/nginx/error.log /var/log/apache2/error.log /usr/local/var/log/php-fpm.log; do [ -f "$f" ] && [ ! -L "$f" ] && grep -EH "$T_PAT" "$f"; done')
  fi
  hits=$(printf '%s\n' "$hits" | sed '/^[[:space:]]*$/d')

  local n; n=$(count_lines "$hits")
  if (( n == 0 )); then
    ok "Tidak ada error memory exhausted / crash worker di log yang terbaca."
    return
  fi
  local ncrash; ncrash=$(grep -cEi 'segfault|SIGSEGV|heap corrupted|signal (6|7|11)|core dumped|general protection' <<<"$hits")
  med "$n baris error memori/crash ($ncrash di antaranya crash). Celah PHP2Shell dipicu saat PHP kehabisan memori / fatal error — cocokkan waktunya dengan access log. 10 terakhir:"
  block "$(tail -n 10 <<<"$hits")" 10
  [[ $TGT == host ]] && info "Log file host tidak difilter tanggal; perhatikan timestamp ≥ $SINCE."
}

check_access_logs() {
  section "3. Access log: POST yang berakhir 5xx (per IP)"
  local logs="" f
  if [[ $TGT == host ]]; then
    for f in /var/log/nginx/*access*.log* /var/log/apache2/*access*.log* /var/log/httpd/*access_log* /usr/local/lsws/logs/access.log*; do
      [[ -f $f && ! -L $f ]] || continue
      if [[ $f == *.gz ]]; then logs+=$(zcat "$f" 2>/dev/null)$'\n'
      else logs+=$(cat "$f" 2>/dev/null)$'\n'; fi
    done
  else
    logs=$(docker logs --since "$SINCE" "$TGT" 2>&1)
  fi

  local top
  top=$(printf '%s\n' "$logs" | awk '{ for (i=1;i<=NF;i++) if ($i=="\"POST") { st=$(i+3); if (st ~ /^50[0-4]$/) print $1; break } }' \
        | sort | uniq -c | sort -rn | head -n 15)

  if [[ -z $(sed '/^[[:space:]]*$/d' <<<"$top") ]]; then
    ok "Tidak ada POST → 5xx di access log yang terbaca (format combined)."
    return
  fi
  local maxc; maxc=$(awk 'NR==1{print $1}' <<<"$top")
  if (( maxc >= 20 )); then
    med "Ada IP dengan banyak POST yang berakhir 5xx (pola khas percobaan exploit berulang). Top IP:"
  else
    info "Beberapa POST berakhir 5xx (jumlah kecil, kemungkinan normal). Top IP:"
  fi
  block "$top" 15
  info "Kalau di belakang reverse proxy/CDN, IP di atas bisa jadi IP proxy. Cek header X-Forwarded-For di WAF/proxy."
}

check_recent_files() {
  section "4. File PHP / config baru atau berubah sejak $SINCE"
  local out
  out=$(run_t "$T_LIB"' wfind -type f \( -name "*.php" -o -name "*.php[0-9]" -o -name "*.phtml" -o -name "*.pht" -o -name "*.phar" -o -name ".user.ini" -o -name ".htaccess" \) -mtime -"$T_DAYS" -print')
  local n; n=$(count_lines "$out")
  if (( n == 0 )); then
    ok "Tidak ada file PHP/.htaccess/.user.ini yang berubah sejak $SINCE di: $CUR_WEB"
  else
    med "$n file PHP/config berubah sejak $SINCE. Normal kalau ada deploy; kalau tidak ada deploy, ini mencurigakan. Daftar:"
    block "$out" 25
  fi

  # PHP di folder upload/media/storage = hampir pasti mencurigakan
  out=$(run_t "$T_LIB"' wfind -type f \( -name "*.php" -o -name "*.php[0-9]" -o -name "*.phtml" -o -name "*.pht" \) \( -path "*/upload*" -o -path "*/Upload*" -o -path "*/media/*" -o -path "*/images/*" -o -path "*/img/*" -o -path "*/storage/app/public/*" -o -path "*/public/storage/*" -o -path "*/files/*" \) ! \( -name "index.php" -size -2k \) -print')
  if [[ -n $(sed '/^[[:space:]]*$/d' <<<"$out") ]]; then
    high "File PHP di folder upload/media/storage (lokasi favorit webshell):"
    block "$out" 20
  else
    ok "Tidak ada file PHP di folder upload/media/storage."
  fi

  # Gambar yang berisi kode PHP
  out=$(run_t "$T_LIB"' wfind -type f \( -name "*.jpg" -o -name "*.jpeg" -o -name "*.png" -o -name "*.gif" -o -name "*.ico" -o -name "*.svg" -o -name "*.webp" \) -size -2048k -exec grep -l "<?php" {} +')
  if [[ -n $(sed '/^[[:space:]]*$/d' <<<"$out") ]]; then
    high "File gambar yang mengandung kode <?php:"
    block "$out" 20
  else
    ok "Tidak ada file gambar berisi kode PHP."
  fi
}

check_webshell_patterns() {
  section "5. Pola webshell / kode obfuscated"
  if [[ $DO_SCAN != 1 ]]; then
    info "Dilewati (dinonaktifkan di wizard/flag)."
    return
  fi
  local pat='eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|\$_(POST|GET|REQUEST|COOKIE|SERVER))|assert[[:space:]]*\([[:space:]]*(\$_|base64_decode)|(system|shell_exec|passthru|popen|proc_open|pcntl_exec)[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE|SERVER|FILES)|[^_a-z]exec[[:space:]]*\([[:space:]]*\$_(POST|GET|REQUEST|COOKIE)|create_function[[:space:]]*\(.*\$_(POST|GET|REQUEST|COOKIE)|FilesMan|b374k|c99shell|r57shell|IndoXploit|AnonymousFox|\$_COOKIE\[[^]]*\][[:space:]]*\)[[:space:]]*;'
  local out
  out=$(T_PAT="$pat" run_t "$T_LIB"' wfind -type f \( -name "*.php" -o -name "*.php[0-9]" -o -name "*.phtml" -o -name "*.inc" \) -size -5120k -exec grep -HnE -m1 "$T_PAT" {} +')
  out=$(sed '/^[[:space:]]*$/d' <<<"$out")
  if [[ -z $out ]]; then
    ok "Tidak ada pola webshell high-signal."
  else
    local core vend
    core=$(grep -v '/vendor/' <<<"$out")
    vend=$(grep '/vendor/' <<<"$out")
    if [[ -n $core ]]; then
      high "Pola webshell ditemukan di $(count_lines "$core") file (di luar vendor). Cek manual satu per satu:"
      block "$core" 20
    fi
    if [[ -n $vend ]]; then
      med "Pola mirip webshell di $(count_lines "$vend") file vendor (sering false positive, tetap lirik):"
      block "$vend" 10
    fi
  fi

  # Baris base64 panjang di file PHP
  out=$(run_t "$T_LIB"' wfind -type f \( -name "*.php" -o -name "*.phtml" \) -size -5120k -exec grep -lE "[A-Za-z0-9+/=]{200,}[A-Za-z0-9+/=]{200,}" {} +' | grep -v '/vendor/' | head -n 50)
  if [[ -n $(sed '/^[[:space:]]*$/d' <<<"$out") ]]; then
    med "File PHP dengan string base64 sangat panjang (bisa payload terenkode, bisa juga aset embed):"
    block "$out" 15
  fi
}

check_persistence() {
  section "6. Persistensi (auto_prepend, /tmp, cron, SSH key, user)"
  local out

  out=$(run_t "$T_LIB"' wfind -type f \( -name ".user.ini" -o -name ".htaccess" -o -name "php.ini" \) -exec grep -HnEi "auto_(prepend|append)_file" {} +')
  if [[ -n $(sed '/^[[:space:]]*$/d' <<<"$out") ]]; then
    high "auto_prepend/append_file di webroot (teknik backdoor klasik; legit hanya untuk WAF seperti Wordfence):"
    block "$out" 10
  else
    ok "Tidak ada auto_prepend/append_file di .user.ini/.htaccess webroot."
  fi

  out=$(run_t 'php -i 2>/dev/null | grep -E "^auto_(prepend|append)_file"' | grep -v 'no value => no value')
  if [[ -n $(sed '/^[[:space:]]*$/d' <<<"$out") ]]; then
    high "auto_prepend/append_file aktif di konfigurasi PHP global:"
    block "$out" 5
  fi

  out=$(run_t 'find /tmp /var/tmp /dev/shm -xdev -type f \( -name "*.php*" -o -name "*.phtml" -o -name "*.sh" -o -name "*.pl" -o -name "*.py" -o -perm -100 \) -mtime -"$T_DAYS" 2>/dev/null | grep -v "/sess_" | head -n 100')
  if [[ -n $(sed '/^[[:space:]]*$/d' <<<"$out") ]]; then
    med "Script/executable baru di /tmp, /var/tmp, /dev/shm:"
    block "$out" 15
  else
    ok "Tidak ada script/executable baru di /tmp, /var/tmp, /dev/shm."
  fi

  out=$(run_t 'for d in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /var/spool/cron /etc/periodic; do [ -e "$d" ] && find "$d" -type f -mtime -"$T_DAYS" 2>/dev/null; done')
  if [[ -n $(sed '/^[[:space:]]*$/d' <<<"$out") ]]; then
    med "File cron berubah sejak $SINCE:"
    block "$out" 10
  else
    ok "Tidak ada file cron yang berubah sejak $SINCE."
  fi

  out=$(run_t 'for f in /var/spool/cron/crontabs/www-data /var/spool/cron/crontabs/nginx /var/spool/cron/crontabs/apache /var/spool/cron/crontabs/http /var/spool/cron/www-data /var/spool/cron/nginx /var/spool/cron/apache; do [ -f "$f" ] && grep -vE "^[[:space:]]*(#|$)" "$f" | sed "s|^|$f: |"; done')
  if [[ -n $(sed '/^[[:space:]]*$/d' <<<"$out") ]]; then
    high "User web server punya crontab (jarang legit):"
    block "$out" 10
  fi

  out=$(run_t 'find /root/.ssh /home /var/www /srv -maxdepth 4 -name "authorized_keys*" -mtime -"$T_DAYS" 2>/dev/null')
  if [[ -n $(sed '/^[[:space:]]*$/d' <<<"$out") ]]; then
    high "authorized_keys berubah sejak $SINCE:"
    block "$out" 10
  else
    ok "Tidak ada authorized_keys yang berubah."
  fi

  out=$(run_t 'awk -F: '"'"'$3==0 && $1!="root"{print}'"'"' /etc/passwd')
  if [[ -n $(sed '/^[[:space:]]*$/d' <<<"$out") ]]; then
    high "User dengan UID 0 selain root:"
    block "$out" 5
  fi

  out=$(run_t 'find /etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d -mtime -"$T_DAYS" 2>/dev/null')
  if [[ -n $(sed '/^[[:space:]]*$/d' <<<"$out") ]]; then
    med "File akun/sudo berubah sejak $SINCE:"
    block "$out" 5
  fi

  out=$(run_t '[ -s /etc/ld.so.preload ] && cat /etc/ld.so.preload')
  if [[ -n $(sed '/^[[:space:]]*$/d' <<<"$out") ]]; then
    high "/etc/ld.so.preload terisi (teknik rootkit userland):"
    block "$out" 5
  fi
}

check_processes() {
  section "7. Proses mencurigakan"
  local ps_out
  if [[ $TGT == host ]]; then
    ps_out=$(ps -eo pid=,ppid=,user=,pcpu=,comm=,args= 2>/dev/null)
  else
    ps_out=$(docker top "$TGT" -eo pid,ppid,user,pcpu,comm,args 2>/dev/null | tail -n +2)
  fi
  if [[ -z $ps_out ]]; then
    info "Tidak bisa membaca daftar proses."
    return
  fi

  local sus
  sus=$(awk '
    { comm[$1]=$5; par[$1]=$2; line[$1]=$0 }
    END {
      for (p in comm) {
        c=comm[p]; pc=comm[par[p]]
        if (c ~ /^(sh|bash|dash|ash|zsh|curl|wget|python[0-9.]*|perl|nc|ncat|netcat|socat|telnet|base64|busybox)$/ &&
            pc ~ /^(php|php[0-9.]+|php-fpm.*|php-cgi.*|apache2|httpd|nginx|frankenphp|lsphp.*)$/) print line[p]
      }
    }' <<<"$ps_out")
  if [[ -n $sus ]]; then
    high "Shell/tool jaringan dengan parent PHP/web server (khas reverse shell; legit hanya kalau app memang memanggil shell_exec):"
    block "$sus" 15
  else
    ok "Tidak ada shell/tool jaringan yang di-spawn oleh PHP/web server."
  fi

  local miner
  miner=$(grep -Ei 'xmrig|kinsing|kdevtmpfsi|minerd|cpuminer|stratum\+tcp|nanominer|\bxmr\b' <<<"$ps_out")
  if [[ -n $miner ]]; then
    high "Proses yang cocok dengan cryptominer populer:"
    block "$miner" 10
  fi

  # Proses yang berjalan dari /tmp, /dev/shm, atau binary yang sudah dihapus (PID host)
  if [[ $EUID -eq 0 ]]; then
    local pid exe bad=""
    while read -r pid _; do
      [[ $pid =~ ^[0-9]+$ ]] || continue
      exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
      if [[ $exe == /tmp/* || $exe == /dev/shm/* || $exe == /var/tmp/* || $exe == *"(deleted)"* ]]; then
        bad+="pid=$pid exe=$exe :: $(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | cut -c1-150)"$'\n'
      fi
    done <<<"$ps_out"
    if [[ -n $(sed '/^[[:space:]]*$/d' <<<"$bad") ]]; then
      high "Proses berjalan dari /tmp, /dev/shm, atau binary yang sudah dihapus:"
      block "$bad" 10
    else
      ok "Tidak ada proses yang berjalan dari /tmp, /dev/shm, atau binary terhapus."
    fi
  else
    info "Cek binary proses (/proc/*/exe) dilewati: perlu root."
  fi

  info "Top 5 proses berdasarkan CPU (cek kalau ada yang asing):"
  block "$(sort -k4 -rn <<<"$ps_out" | head -n 5 | awk '{$1=$1; print}')" 5
}

check_network() {
  section "8. Koneksi jaringan"
  local est lis
  if [[ $TGT == host ]]; then
    command -v ss >/dev/null 2>&1 || { info "Perintah ss tidak tersedia, dilewati."; return; }
    est=$(ss -tnpH state established 2>/dev/null)
    lis=$(ss -tlnpH 2>/dev/null)
  else
    local cpid; cpid=$(docker inspect -f '{{.State.Pid}}' "$TGT" 2>/dev/null)
    if [[ $EUID -eq 0 && -n $cpid && $cpid != 0 ]] && command -v nsenter >/dev/null 2>&1 && command -v ss >/dev/null 2>&1; then
      est=$(nsenter -t "$cpid" -n ss -tnpH state established 2>/dev/null)
      lis=$(nsenter -t "$cpid" -n ss -tlnpH 2>/dev/null)
    else
      info "Cek jaringan container perlu root + nsenter + ss di host. Dilewati."
      return
    fi
  fi

  local badproc='"(sh|bash|dash|ash|perl|python[0-9.]*|nc|ncat|socat|telnet|curl|wget)"'
  local sus; sus=$(grep -E "users:\(\($badproc" <<<"$est"$'\n'"$lis")
  if [[ -n $(sed '/^[[:space:]]*$/d' <<<"$sus") ]]; then
    high "Shell/interpreter memegang koneksi jaringan (reverse/bind shell?):"
    block "$sus" 10
  else
    ok "Tidak ada shell/interpreter yang memegang koneksi jaringan."
  fi

  local pub
  pub=$(awk '{print $4, $5}' <<<"$est" \
        | grep -vE '^(\[?::ffff:)?(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.)|^\[?(::1|fe80|fd)' \
        | grep -Ei 'php|apache|httpd|nginx|franken|lsphp|www' | sort | uniq -c | sort -rn | head -n 15)
  if [[ -n $(sed '/^[[:space:]]*$/d' <<<"$pub") ]]; then
    info "Koneksi keluar ke IP publik dari proses web/PHP (bisa API legit; cek yang asing):"
    block "$pub" 15
  fi
}

check_container_config() {
  section "9. Konfigurasi container (risiko kalau container jebol)"
  local priv user pidm netm caps mounts img created
  priv=$(docker inspect -f '{{.HostConfig.Privileged}}' "$TGT" 2>/dev/null)
  user=$(docker inspect -f '{{.Config.User}}' "$TGT" 2>/dev/null)
  pidm=$(docker inspect -f '{{.HostConfig.PidMode}}' "$TGT" 2>/dev/null)
  netm=$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$TGT" 2>/dev/null)
  caps=$(docker inspect -f '{{.HostConfig.CapAdd}}' "$TGT" 2>/dev/null)
  mounts=$(docker inspect -f '{{range .Mounts}}{{.Source}} -> {{.Destination}} (rw={{.RW}}){{"\n"}}{{end}}' "$TGT" 2>/dev/null)
  img=$(docker inspect -f '{{.Image}}' "$TGT" 2>/dev/null)
  created=$(docker image inspect -f '{{.Created}}' "$img" 2>/dev/null)

  [[ $priv == true ]] && med "RISIKO: container berjalan --privileged (escape ke host mudah)."
  grep -q 'docker.sock' <<<"$mounts" && med "RISIKO: /var/run/docker.sock di-mount (shell di container = kontrol penuh Docker host)."
  [[ $pidm == host ]] && med "RISIKO: PidMode=host."
  [[ $netm == host ]] && info "NetworkMode=host (container berbagi jaringan host)."
  [[ -n $caps && $caps != "[]" && $caps != "<no value>" ]] && info "Capability tambahan: $caps"
  [[ -z $user || $user == root || $user == 0 || $user == 0:0 ]] && info "User container: root (default). Worker PHP-FPM biasanya tetap www-data, tapi pertimbangkan non-root."
  if [[ -n $created && $created < $PATCH_DATE ]]; then
    med "Image dibuild ${created%%T*}, sebelum patch $PATCH_DATE. Pull ulang base image & rebuild (--pull --no-cache)."
  fi
  if [[ -n $(sed '/^[[:space:]]*$/d' <<<"$mounts") ]]; then
    info "Mount (folder bind-mount TIDAK ikut bersih saat rebuild container; cek isinya juga):"
    block "$mounts" 10
  fi
}

check_docker_diff() {
  section "10. docker diff (file yang berubah dibanding image)"
  local d
  d=$(docker diff "$TGT" 2>/dev/null | grep -vE '^[ACD] /(proc|sys|dev|run|var/run|var/log|var/cache|var/lib/php/sessions|tmp/sess_)|^C /(tmp|var|etc|root|usr|usr/local|home)?$')
  if [[ -z $(sed '/^[[:space:]]*$/d' <<<"$d") ]]; then
    ok "Tidak ada perubahan berarti di filesystem container."
    return
  fi
  local php; php=$(grep -E '^[AC] .*\.(php[0-9]?|phtml|pht|phar)$|^[AC] .*/(\.user\.ini|\.htaccess)$' <<<"$d")
  if [[ -n $php ]]; then
    high "File PHP/config ditambah (A) atau diubah (C) di dalam container setelah start. Di image yang immutable, ini sangat mencurigakan:"
    block "$php" 20
  fi
  local added; added=$(grep -E '^A ' <<<"$d" | grep -vE '\.(php[0-9]?|phtml|pht|phar)$')
  if [[ -n $added ]]; then
    med "$(count_lines "$added") file/folder lain ditambahkan sejak container start (cek yang asing; cache app biasanya normal):"
    block "$added" 20
  fi
}

# =============================================================================
#  WIZARD & ARGUMEN
# =============================================================================
usage() {
  cat <<EOF
php2shell-check.sh v$VER — triage read-only PHP2Shell (CVE-2026-109618/109619)

Tanpa argumen  : mode wizard interaktif.
  -y               non-interaktif (pakai default / flag)
  -m MODE          host | docker | both            (default: host)
  -c CONTAINERS    nama dipisah koma, atau "all" = semua container ber-PHP
  -w "DIR DIR"     webroot (host). Default: auto-detect
  -s YYYY-MM-DD    cek perubahan sejak tanggal ini (default: $SINCE_DEFAULT)
  -o FILE          file laporan
  --no-scan        lewati scan pola webshell (lebih cepat)
  --include-vendor ikut scan folder vendor/ (lebih lambat, lebih banyak false positive)
  -h               bantuan
EOF
}

ARGC=$#
MODE="host"; CONTAINERS=""; WEB_HOST=""; SINCE="$SINCE_DEFAULT"; OUT=""
DO_SCAN=1; EXCL_VENDOR=1; NONINT=0

while [[ $# -gt 0 ]]; do
  case $1 in
    -y) NONINT=1 ;;
    -m) MODE=${2:-}; shift ;;
    -c) CONTAINERS=${2:-}; shift ;;
    -w) WEB_HOST=${2:-}; shift ;;
    -s) SINCE=${2:-}; shift ;;
    -o) OUT=${2:-}; shift ;;
    --no-scan) DO_SCAN=0 ;;
    --include-vendor) EXCL_VENDOR=0 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Argumen tidak dikenal: $1 (lihat -h)" ;;
  esac
  shift
done

ask() {  # ask "pertanyaan" "default"
  local ans
  read -r -p "$(printf '%s %s[%s]%s: ' "$1" "$C" "$2" "$N")" ans </dev/tty
  printf '%s' "${ans:-$2}"
}
yesno() { [[ $(ask "$1 (y/n)" "$2") =~ ^[Yy] ]]; }

detect_host_webroots() {
  local d found=""
  for d in /var/www /srv/www /srv/http /usr/share/nginx/html /home/*/public_html /opt/lampp/htdocs; do
    [[ -d $d ]] && found+="$d "
  done
  printf '%s' "${found% }"
}

has_php() { docker exec "$1" sh -c 'command -v php || command -v php-fpm || command -v frankenphp || ls /usr/local/sbin/php-fpm' >/dev/null 2>&1; }

list_php_containers() {
  local c
  for c in $(docker ps --format '{{.Names}}'); do has_php "$c" && printf '%s\n' "$c"; done
}

wizard() {
  printf '\n%s\n' "${BD}=== PHP2Shell Check v$VER — wizard ===${N}"
  printf '%s\n\n' "Script ini read-only: tidak mengubah apa pun, hanya membaca & membuat laporan."

  printf '%s\n' "Target yang mau dicek:"
  printf '%s\n' "  1) Host (server langsung, PHP terpasang di OS)"
  printf '%s\n' "  2) Container Docker"
  printf '%s\n' "  3) Keduanya"
  case $(ask "Pilih" "1") in
    2) MODE=docker ;; 3) MODE=both ;; *) MODE=host ;;
  esac

  if [[ $MODE != docker ]]; then
    local def; def=$(detect_host_webroots); [[ -z $def ]] && def="/var/www"
    WEB_HOST=$(ask "Webroot host (pisahkan spasi kalau lebih dari satu)" "$def")
  fi

  if [[ $MODE != host ]]; then
    command -v docker >/dev/null 2>&1 || die "docker tidak ditemukan."
    printf '\n%s\n' "Container yang sedang berjalan (mengecek mana yang ber-PHP...):"
    local i=0 c names=()
    while read -r c; do
      [[ -z $c ]] && continue
      i=$((i+1)); names+=("$c")
      if has_php "$c"; then printf '  %2d) %s %s[PHP]%s\n' "$i" "$c" "$G" "$N"
      else printf '  %2d) %s\n' "$i" "$c"; fi
    done < <(docker ps --format '{{.Names}}')
    (( i == 0 )) && die "Tidak ada container yang berjalan."
    local sel; sel=$(ask "Pilih nomor (mis. 1,3) atau 'all' untuk semua yang ber-PHP" "all")
    if [[ $sel == all ]]; then
      CONTAINERS="all"
    else
      CONTAINERS=""
      local n
      for n in ${sel//,/ }; do
        [[ $n =~ ^[0-9]+$ ]] && (( n>=1 && n<=i )) && CONTAINERS+="${names[$((n-1))]},"
      done
      CONTAINERS=${CONTAINERS%,}
      [[ -z $CONTAINERS ]] && die "Pilihan container tidak valid."
    fi
  fi

  echo
  SINCE=$(ask "Cek perubahan sejak tanggal (YYYY-MM-DD; leak publik 20 Okt)" "$SINCE")
  if yesno "Scan isi file untuk pola webshell? (lebih lama di webroot besar)" "y"; then DO_SCAN=1; else DO_SCAN=0; fi
  if [[ $DO_SCAN == 1 ]]; then
    if yesno "Lewati folder vendor/ saat scan? (disarankan)" "y"; then EXCL_VENDOR=1; else EXCL_VENDOR=0; fi
  fi
  OUT=$(ask "Simpan laporan ke" "${OUT:-./php2shell-report-$(hostname)-$(date +%Y%m%d-%H%M).txt}")

  printf '\n%s\n' "${BD}Ringkasan:${N} mode=$MODE  sejak=$SINCE  scan=$([[ $DO_SCAN == 1 ]] && echo ya || echo tidak)"
  [[ $MODE != docker ]] && printf '  webroot host : %s\n' "$WEB_HOST"
  [[ $MODE != host ]]   && printf '  container    : %s\n' "$CONTAINERS"
  yesno "Lanjut?" "y" || { echo "Dibatalkan."; exit 0; }
}

# =============================================================================
#  MAIN
# =============================================================================
if [[ $NONINT -eq 0 && $ARGC -eq 0 ]]; then
  [[ -r /dev/tty ]] || die "Tidak ada terminal interaktif; pakai -y."
  wizard
fi

[[ $MODE =~ ^(host|docker|both)$ ]] || die "Mode harus host, docker, atau both."
since_ts=$(date -d "$SINCE" +%s 2>/dev/null) || die "Format tanggal salah: $SINCE (pakai YYYY-MM-DD)"
DAYS=$(( ( $(date +%s) - since_ts ) / 86400 + 1 ))
(( DAYS < 1 )) && DAYS=1
[[ -z $WEB_HOST ]] && WEB_HOST=$(detect_host_webroots)
[[ -z $WEB_HOST ]] && WEB_HOST="/var/www"
OUT=${OUT:-./php2shell-report-$(hostname)-$(date +%Y%m%d-%H%M).txt}

: >"$OUT" 2>/dev/null || die "Tidak bisa menulis laporan ke $OUT"
REPORT="$OUT"

log "${BD}PHP2Shell Check v$VER${N} — $(date '+%Y-%m-%d %H:%M %Z') — host: $(hostname)"
log "Mode: $MODE | sejak: $SINCE ($DAYS hari) | scan webshell: $DO_SCAN | skip vendor: $EXCL_VENDOR"
[[ $EUID -ne 0 ]] && log "${Y}Peringatan: tidak dijalankan sebagai root — sebagian file/log/proses tidak terbaca. Disarankan pakai sudo.${N}"

# ---- Host ----
if [[ $MODE == host || $MODE == both ]]; then
  TGT="host"; TGT_LABEL="host"; CUR_WEB="$WEB_HOST"
  log ""; log "${BD}████ TARGET: HOST ($(hostname)) — webroot: $CUR_WEB ████${N}"
  check_php_version
  check_error_logs
  check_access_logs
  check_recent_files
  check_webshell_patterns
  check_persistence
  check_processes
  check_network
fi

# ---- Container ----
if [[ $MODE == docker || $MODE == both ]]; then
  command -v docker >/dev/null 2>&1 || die "docker tidak ditemukan."
  if [[ -z $CONTAINERS || $CONTAINERS == all ]]; then
    mapfile -t CLIST < <(list_php_containers)
  else
    IFS=',' read -r -a CLIST <<<"$CONTAINERS"
  fi
  (( ${#CLIST[@]} == 0 )) && log "${Y}Tidak ada container ber-PHP yang ditemukan.${N}"

  for c in "${CLIST[@]}"; do
    [[ -z $c ]] && continue
    TGT="$c"; TGT_LABEL="container:$c"
    if ! docker exec "$c" sh -c 'true' >/dev/null 2>&1; then
      log ""; log "${Y}Container $c tidak bisa di-exec (tidak berjalan / tanpa shell). Hanya cek config & diff.${N}"
      check_container_config; check_docker_diff
      continue
    fi
    # auto-detect webroot di container
    wd=$(docker inspect -f '{{.Config.WorkingDir}}' "$c" 2>/dev/null)
    CUR_WEB=$(docker exec "$c" sh -c 'for d in "$0" /var/www /app /srv /usr/share/nginx/html /opt/app /code; do [ -n "$d" ] && [ "$d" != "/" ] && [ -d "$d" ] && echo "$d"; done' "$wd" 2>/dev/null | sort -u | awk 'NR>1 && index($0, prev"/")==1 {next} {print; prev=$0}' | tr '\n' ' ')
    CUR_WEB=${CUR_WEB% }
    [[ -z $CUR_WEB ]] && CUR_WEB="/var/www"
    log ""; log "${BD}████ TARGET: CONTAINER $c ($(docker inspect -f '{{.Config.Image}}' "$c" 2>/dev/null)) — webroot: $CUR_WEB ████${N}"
    check_php_version
    check_error_logs
    check_access_logs
    check_recent_files
    check_webshell_patterns
    check_persistence
    check_processes
    check_network
    check_container_config
    check_docker_diff
  done
fi

# ---- Ringkasan ----
log ""
log "${BD}════════════════ RINGKASAN ════════════════${N}"
if (( NH > 0 )); then
  log "${R}${BD}HIGH: $NH${N}"
  for h in "${HIGHS[@]}"; do log "  - ${h:0:200}"; done
fi
if (( NM > 0 )); then
  log "${Y}${BD}MED : $NM${N}"
  for m in "${MEDS[@]}"; do log "  - ${m:0:200}"; done
fi
(( NH == 0 && NM == 0 )) && log "${G}Tidak ada temuan.${N} (Ini bukan jaminan bersih; tetap patch & pantau.)"

log ""
log "${BD}Langkah berikutnya:${N}"
if (( NH > 0 )); then
  log "  1. Anggap target dengan HIGH sebagai kemungkinan sudah jebol. Isolasi kalau perlu, SIMPAN bukti (log, file, docker diff) sebelum dihapus."
  log "  2. Rebuild dari image/server bersih yang PHP-nya sudah dipatch — jangan cuma hapus file webshell."
  log "  3. Rotasi semua secret: password DB, API key, .env, SSH key, token cloud."
  log "  4. Cek DB dan service lain yang bisa diakses dari target itu."
else
  log "  1. Pastikan PHP sudah ≥ 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (atau backport distro)."
  log "  2. Untuk Docker: docker build --pull --no-cache, lalu redeploy."
  log "  3. Ulangi script ini beberapa hari ke depan; exploit sudah aktif di lapangan."
fi
log ""
log "Laporan lengkap: $OUT"

(( NH > 0 )) && exit 2
(( NM > 0 )) && exit 1
exit 0
