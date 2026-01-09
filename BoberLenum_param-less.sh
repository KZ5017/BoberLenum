#!/usr/bin/env bash
set -e
cat << 'BANNER'

                           #########                                       
                #####   ###         ###    #####                           
              ##     ####              ####    ##                          
              ##  ##                        ##  ##                         
               ##       ###         ###        ##                          
                 ##                         ##                             
                ##      ###         ###      ##                            
               ##       ###         ###       ##                           
               #                                #                          
              #             #######             ##                         
             #             #       ##            #                         
              ##     ##    ##     ##   ###      ##                         
              ##      ##     #####     ##       ##                         
              ##       ###     ##     ##        #      #######             
               #          ##### #####          ##    ##       ###          
                #           # # ###           ##    #    ## ##  ###        
                #           #######           ##   ##      ##     ##       
              ###                              ##  ##  ####  ## ## ##      
             ##                                  ###   ####   ##    #      
            ##                 #                  #   ##  ####  ##  ##     
           ##        ##   ###      ###   ##        ##  ##  ###    # ##     
           #          ####            ###           #   ###   ####  ##     
          ##  ##       ##              ##       ##  ## ## ##  ####  ##     
          #    ##       #             ##       ##   ##     ####    ##      
         ##      ##   ###             ####  ###      #  ## ####   ###      
         ##         ####                ####         #   ###      #        
         ##          #                   ##          #  ## ##   ##         
         ##          #                   ##          #         ##          
          ##         #                   ##         ##      ###            
          ##   #######                   ########   #     ###              
            ###      ##                 ###      #########                 
           ##   ## #  ###################  #  #   ##                       
            ############                ###########                   
     ▄▄▄▄·       ▄▄▄▄· ▄▄▄ .▄▄▄  ▄▄▌  ▄▄▄ . ▐ ▄ ▄• ▄▌• ▌ ▄ ·. 
     ▐█ ▀█▪▪     ▐█ ▀█▪▀▄.▀·▀▄ █·██•  ▀▄.▀·•█▌▐██▪██▌·██ ▐███▪
     ▐█▀▀█▄ ▄█▀▄ ▐█▀▀█▄▐▀▀▪▄▐▀▀▄ ██▪  ▐▀▀▪▄▐█▐▐▌█▌▐█▌▐█ ▌▐▌▐█·
     ██▄▪▐█▐█▌.▐▌██▄▪▐█▐█▄▄▌▐█•█▌▐█▌▐▌▐█▄▄▌██▐█▌▐█▄█▌██ ██▌▐█▌
     ·▀▀▀▀  ▀█▄▀▪·▀▀▀▀  ▀▀▀ .▀  ▀.▀▀▀  ▀▀▀ ▀▀ █▪ ▀▀▀ ▀▀  █▪▀▀▀

BANNER
set -o errexit
set -o nounset
set -o pipefail
print_banner() {
  echo "=== BoberLenum enumeration run ==="
  echo "Time: $(date '+%Y-%m-%d %H:%M:%S')"
  echo
}
# ---- Enumeration flow (preserve order and behavior) ----
print_banner
# countdown in 3 seconds
for i in 3 2 1; do
  printf "\rContinue %d..." "$i"
  sleep 1
done
printf "\r                 \r"

RESET="\033[0m"
BOLD="\033[1m"
GREEN="\033[32m"
RED="\033[31m"
BLUE="\033[34m"
CYAN="\033[36m"

print_section() {
  local title="$1"
  echo
  printf "${BLUE}${BOLD}===============================================================================${RESET}\n"
  printf "${BLUE}${BOLD}[ %s ]${RESET}\n" "$title"
  printf "${BLUE}${BOLD}===============================================================================${RESET}\n"
  echo
}

print_subsection() {
  local title="$1"
  printf "${CYAN}${BOLD}=== %s ===${RESET}\n" "$title"
  echo
}

print_sub_subsection() {
  local title="$1"
  printf "${GREEN}${BOLD}[ %s ]${RESET}\n" "$title"
  echo
}

print_finding() {
  local msg="$1"
  printf "${RED}${BOLD}>>> %s${RESET}\n" "$msg"
}
run_cmd() {
  set +e
  local output
  output=$("$@" 2>&1)
  local rc=$?
  set -e
  echo "$output"
  if (( rc != 0 )); then
    echo "Exit code: $rc"
  fi
  echo
}
ansi_reset() {
  printf "\033[0m"
}
check_tools() {
  declare -A TOOL_CATEGORIES=(
    [wget]="Network"
    [curl]="Network"
    [ftp]="Network"
    [tftp]="Network"
    [scp]="Network"
    [sftp]="Network"
    [ssh]="Network"
    [telnet]="Network"
    [nc]="Network"
    [ncat]="Network"
    [socat]="Network"
    [openssl]="Network"
    [python]="Interpreter"
    [python2]="Interpreter"
    [python3]="Interpreter"
    [pip]="Interpreter"
    [pip3]="Interpreter"
    [perl]="Interpreter"
    [ruby]="Interpreter"
    [php]="Interpreter"
    [node]="Interpreter"
    [npm]="Interpreter"
    [lua]="Interpreter"
    [java]="Interpreter"
    [javac]="Interpreter"
    [gcc]="Compiler"
    [cc]="Compiler"
    [clang]="Compiler"
    [make]="Compiler"
    [ld]="Compiler"
    [objdump]="Compiler"
    [objcopy]="Compiler"
    [strip]="Compiler"
    [find]="LOLBins"
    [tar]="LOLBins"
    [zip]="LOLBins"
    [unzip]="LOLBins"
    [rsync]="LOLBins"
    [awk]="LOLBins"
    [sed]="LOLBins"
    [less]="LOLBins"
    [more]="LOLBins"
    [nano]="LOLBins"
    [vim]="LOLBins"
    [vi]="LOLBins"
    [env]="LOLBins"
    [timeout]="LOLBins"
    [docker]="Container"
    [docker-compose]="Container"
    [podman]="Container"
    [kubectl]="Container"
    [crictl]="Container"
    [ctr]="Container"
    [ip]="Recon"
    [ss]="Recon"
    [netstat]="Recon"
    [arp]="Recon"
    [arping]="Recon"
    [route]="Recon"
    [ping]="Recon"
    [traceroute]="Recon"
    [nmap]="Recon"
    [strace]="Debug"
    [ltrace]="Debug"
    [ps]="Debug"
    [pstree]="Debug"
    [top]="Debug"
    [htop]="Debug"
    [watch]="Debug"
    [7z]="Archive"
    [7za]="Archive"
    [gzip]="Archive"
    [gunzip]="Archive"
    [xz]="Archive"
    [lzma]="Archive"
    [base64]="Archive"
    [sudo]="Privilege"
    [su]="Privilege"
    [passwd]="Privilege"
    [newgrp]="Privilege"
    [chsh]="Privilege"
  )
  declare -A FOUND_BY_CAT=()
  for tool in "${!TOOL_CATEGORIES[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
      cat="${TOOL_CATEGORIES[$tool]}"
      FOUND_BY_CAT["$cat"]+="$tool "
    fi
  done
  for cat in Network Interpreter Compiler LOLBins Container Recon Debug Archive Privilege; do
    if [[ -n "${FOUND_BY_CAT[$cat]:-}" ]]; then
      print_sub_subsection "$cat"
      for t in ${FOUND_BY_CAT[$cat]}; do
        printf "  %s\n" "$t"
      done
      echo
    fi
  done
}
systemd_custom_units() {
    local findings=0
    if ls /etc/systemd/system/*.service >/dev/null 2>&1; then
        ls -la /etc/systemd/system/*.service
        echo
    else
        echo "-- No custom .service files found --"
        echo
    fi
}
profile_d_info() {
    local findings=0
    if [[ -d /etc/profile.d ]]; then
        ls -la /etc/profile.d
        echo
    else
        echo "-- /etc/profile.d missing --"
        echo
        return
    fi
}
show_user_info() {
  local user="${1:-}"
  set +u
  local pw_entry
  pw_entry=$(getent passwd -- "$user" 2>/dev/null || true)
  local rc_pw=$?
  set -u
  if (( rc_pw == 0 )) && [[ -n "${pw_entry:-}" ]]; then
    IFS=':' read -r uname passwd uid gid gecos home shell <<< "${pw_entry}"
    uname="${uname:-$user}"
    uid="${uid:-?}"
    gid="${gid:-?}"
    home="${home:-/nonexistent}"
    shell="${shell:-/bin/sh}"
    print_sub_subsection "Username: $uname"
    echo "UID: $uid"
    echo "GID: $gid"
    echo "Home: $home"
    echo "Shell: $shell"
    if [[ -n "${gecos:-}" ]]; then
      echo "GECOS: $gecos"
    fi
  else
    echo "No passwd entry found for $user"
    home="/nonexistent"
  fi
  set +u
  local id_out
  id_out=$(id -- "$user" 2>&1) || id_out="$?"
  local rc_id=$?
  set -u
  if (( rc_id == 0 )); then
    echo "id: $id_out"
  else
    echo "id: (could not retrieve) $id_out"
  fi
  if command -v lastlog >/dev/null 2>&1; then
    set +u
    local lastlog_out
    lastlog_out=$(lastlog -u -- "$user" 2>&1) || lastlog_out=""
    local rc_ll=$?
    set -u
    if (( rc_ll == 0 )) && [[ -n "${lastlog_out:-}" ]]; then
      echo "Last login:"
      printf '%s\n' "$lastlog_out" | sed -n '2,$p'
    else
      echo "Last login: (no record or cannot access) ${lastlog_out:-}"
    fi
  else
    echo "Last login: lastlog not available on system"
  fi
  if [[ -n "${home:-}" && -d "$home" ]]; then
    set +u
    local stat_out
    stat_out=$(stat -c 'Owner: %U, Group: %G, Perm: %a (%A), Modified: %y' -- "$home" 2>&1) || stat_out=""
    local rc_stat=$?
    set -u
    if (( rc_stat == 0 )); then
      echo "Home dir: $stat_out"
    else
      echo "Home dir: (stat failed) ${stat_out:-}"
    fi
    if [[ -d "$home/.ssh" ]]; then
      print_finding ".ssh directory exists"
      if [[ -f "$home/.ssh/authorized_keys" ]]; then
        print_finding "authorized_keys: present"
      else
        echo "authorized_keys: not present"
      fi
    else
      echo ".ssh directory: not present"
    fi
    for hist in .bash_history .zsh_history .profile; do
      if [[ -f "$home/$hist" ]]; then
        set +u
        local hstat
        hstat=$(stat -c '%s bytes, modified %y' -- "$home/$hist" 2>/dev/null || true)
        set -u
        print_finding "History file $hist: ${hstat:-(stat failed)}"
      fi
    done
  else
    echo "Home directory: not present or not accessible"
  fi
  set +u
  local emails=()
  if [[ -n "${gecos:-}" ]]; then
    while IFS= read -r e; do
      emails+=("$e")
    done < <(printf '%s\n' "${gecos}" | grep -Eo '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' || true)
  fi
  for spool in "/var/mail/$user" "/var/spool/mail/$user"; do
    if [[ -r "$spool" ]]; then
      while IFS= read -r e; do
        emails+=("$e")
      done < <(head -n 50 "$spool" 2>/dev/null | grep -Eo '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' || true)
    fi
  done
  set -u
  if (( ${#emails[@]} )); then
    declare -A _seen
    local uniq=()
    for e in "${emails[@]}"; do
      e="$(printf '%s' "$e" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      if [[ -n "$e" && -z "${_seen[$e]:-}" ]]; then
        _seen["$e"]=1
        uniq+=("$e")
      fi
    done
    if (( ${#uniq[@]} )); then
      print_finding "Possible email addresses related to $user:"
      for e in "${uniq[@]}"; do
        echo "$e"
      done
    else
      echo "No email addresses found for $user (GECOS/spool checked)."
    fi
  else
    echo "No email addresses found for $user (GECOS/spool checked)."
  fi
  set +u
  local crontab_out
  crontab_out=$(crontab -l -u -- "$user" 2>&1)
  local rc_cron=$?
  set -u
  if (( rc_cron == 0 )); then
    print_finding "Crontab entries for $user:"
    printf '%s\n' "$crontab_out"
  else
    if [[ -n "${crontab_out:-}" ]]; then
      echo "Crontab: not available via crontab -l (message: $crontab_out)"
    else
      echo "Crontab: not available via crontab -l (exit code: $rc_cron)"
    fi
    if [[ -r "/var/spool/cron/crontabs/$user" ]]; then
      print_finding "Spool /var/spool/cron/crontabs/$user:"
      set +u
      local spool_out
      spool_out=$(cat -- "/var/spool/cron/crontabs/$user" 2>&1) || spool_out=""
      set -u
      printf '%s\n' "$spool_out"
    elif [[ -r "/var/spool/cron/$user" ]]; then
      print_finding "Spool /var/spool/cron/$user:"
      set +u
      spool_out=$(cat -- "/var/spool/cron/$user" 2>&1) || spool_out=""
      set -u
      printf '%s\n' "$spool_out"
    else
      echo "No spool file readable for $user (no permission or file missing)."
    fi
  fi
  set +u
  local current_user
  current_user="$(id -un 2>/dev/null || true)"
  set -u
  if [[ "$current_user" == "$user" ]]; then
    echo "Find: skipped for $user (do not run find on the invoking user's own files)."
    echo
  else
    set +u
    local find_cmd
    if command -v timeout >/dev/null 2>&1; then
      find_cmd=(timeout 60s find / -path /proc -prune -o \( -type f -o -type d \) -user "$user" \( -exec test -r {} \; -o -exec test -w {} \; -o -exec test -x {} \; \) -ls)
    else
      find_cmd=(find / -path /proc -prune -o \( -type f -o -type d \) -user "$user" \( -exec test -r {} \; -o -exec test -w {} \; -o -exec test -x {} \; \) -ls)
    fi
    print_subsection_warn "find owned readable/writable/executable by $user (/proc NOT scanned!)"
    set +e
    local find_out
    find_out="$("${find_cmd[@]}" 2>/dev/null || true)"
    local rc_find=$?
    set -e

    if [[ -n "${find_out:-}" ]]; then
      echo "$find_out"
    else
      if (( rc_find == 124 )); then
        echo "Find: timed out (timeout reached)."
      else
        echo "Find: no readable/writable/executable entries found for $user or permission denied."
      fi
    fi
    echo
    set -u
  fi
  echo
}
enumerate_home_users() {
  print_subsection "ls -la /home/"
  set +e
  ls -la /home/ 2>&1
  local rc_ls=$?
  set -e
  if (( rc_ls != 0 )); then
    echo "Note: ls -la /home/ returned exit code $rc_ls"
  fi
  echo
  print_subsection "list of users with home directory"
  local entry
  for entry in /home/*; do
    if [[ -d "$entry" ]]; then
      local user
      user=$(basename "$entry")
      set +e
      show_user_info "$user"
      local rc_show=$?
      set -e
      if (( rc_show != 0 )); then
        echo "Warning: show_user_info for user $user exited with code $rc_show, continuing with next user"
      fi
    fi
  done
}
ip_info(){
    if command -v ip >/dev/null 2>&1; then
        run_cmd ip addr
    elif command -v ifconfig >/dev/null 2>&1; then
        run_cmd ifconfig -a
    else
        echo "-- ip/ifconfig is not found --"
        echo "Neither ip nor ss is available on this system; cannot list ip info."
    fi  
}
hosts_info(){
    if [[ -r /etc/hosts ]]; then
        run_cmd cat /etc/hosts
    else
        echo "-- /etc/hosts (unreadable or missing) --"
        echo "/etc/hosts not readable or does not exist"
        echo
    fi
}
resolv_info(){
    if [[ -e /etc/resolv.conf ]]; then
        if [[ -L /etc/resolv.conf ]]; then
            run_cmd ls -l /etc/resolv.conf
        fi
        if [[ -r /etc/resolv.conf ]]; then
            run_cmd cat /etc/resolv.conf
        else
            echo "-- /etc/resolv.conf (unreadable) --"
            echo "/etc/resolv.conf exists but is not readable"
            echo
        fi
    else
        echo "-- /etc/resolv.conf (missing) --"
        echo "/etc/resolv.conf does not exist"
        echo
    fi
}
netstat_info(){
    if command -v netstat >/dev/null 2>&1; then
        run_cmd netstat -lntup
    elif command -v ss >/dev/null 2>&1; then
        run_cmd ss -lntup
    else
        echo "-- netstat/ss not found --"
        echo "Neither netstat nor ss is available on this system; cannot list listening sockets with process info."
        echo
    fi
}
lsblk_info() {
    if ! command -v lsblk >/dev/null 2>&1; then
        return
    fi
    lsblk -o NAME,MAJ:MIN,SIZE,FSTYPE,MOUNTPOINT
    echo
    local root_dev
    root_dev=$(findmnt -n -o SOURCE / 2>/dev/null | sed 's|/dev/||')

    while IFS= read -r line; do
        name=$(awk '{print $1}' <<< "$line")
        mountpoint=$(awk '{print $4}' <<< "$line")

        [[ "$name" == "NAME" ]] && continue

        if [[ -n "$mountpoint" && "$mountpoint" != "/" ]]; then
            print_finding "Additional block device mounted: /dev/$name -> $mountpoint"
        fi
    done < <(lsblk -n -o NAME,SIZE,FSTYPE,MOUNTPOINT)
    echo
}
mount_info() {
    if ! command -v findmnt >/dev/null 2>&1; then
        run_cmd mount
        return
    fi
    findmnt -ro TARGET,SOURCE,SIZE,FSTYPE,OPTIONS
    echo
    local findings=0
    while IFS= read -r line; do
        target=$(awk '{print $1}' <<< "$line")
        source=$(awk '{print $2}' <<< "$line")
        size=$(awk '{print $3}' <<< "$line")
        fstype=$(awk '{print $4}' <<< "$line")
        if [[ "$target" =~ ^(/|/boot|/boot/efi|/proc|/sys|/dev|/run|/usr|/lib|/var)(/|$) ]]; then
            continue
        fi
        if [[ "$target" =~ ^(/mnt|/media|/opt|/srv|/tmp|/home|/data|/backup|/exports|/shared) ]]; then
            print_finding "Non-standard mount detected: $target ($fstype, $size) <- $source"
            findings=1
        fi
    done < <(findmnt -ro TARGET,SOURCE,SIZE,FSTYPE)

    if [[ $findings -eq 0 ]]; then
        :
    fi
    echo
}
exports_info() {
    if [[ ! -e /etc/exports ]]; then
        echo "-- /etc/exports (missing) --"
        echo "/etc/exports does not exist"
        echo
        return
    fi
    if [[ ! -r /etc/exports ]]; then
        echo "-- /etc/exports (unreadable) --"
        echo "/etc/exports exists but is not readable"
        echo
        return
    fi
    run_cmd cat /etc/exports
    local findings=0
    if grep -qE 'no_root_squash' /etc/exports; then
        print_finding "NFS export uses no_root_squash (root privilege passthrough)"
        findings=1
    fi
    if grep -qE '\(.*rw' /etc/exports; then
        print_finding "Writable NFS export detected (rw)"
        findings=1
    fi
    if grep -qE '(^|[[:space:]])\*' /etc/exports; then
        print_finding "NFS export allows all hosts (*)"
        findings=1
    fi
    if grep -qE 'insecure' /etc/exports; then
        print_finding "NFS export allows insecure ports"
        findings=1
    fi
    if grep -qE 'sync' /etc/exports; then
        print_finding "NFS export uses sync option (performance hint, review context)"
        findings=1
    fi
    if [[ $findings -eq 0 ]]; then
        # opcionális: csendben is hagyhatod
        :
    fi
    echo
}
crontab_info() {
    if [[ -r /etc/crontab ]]; then
        run_cmd cat /etc/crontab
    else
        echo "-- /etc/crontab (unreadable or missing) --"
        echo "/etc/crontab not readable or does not exist"
        echo
    fi
    local user_cron
    user_cron=$(crontab -l 2>/dev/null || true)

    if [[ -n "$user_cron" ]]; then
        echo "-- User crontab --"
        echo "$user_cron"
        echo
        while IFS= read -r line; do
            [[ "$line" =~ ^#|^$ ]] && continue
            cmd=$(echo "$line" | awk '{for (i=6; i<=NF; i++) printf $i " ";}')
            if [[ "$cmd" != */usr/bin/* && "$cmd" != */bin/* && "$cmd" != */usr/sbin/* ]]; then
                print_finding "Cron job executes non-standard path: $cmd"
            fi
        done <<< "$user_cron"
    else
        echo "-- User crontab --"
        echo "No user crontab entries"
        echo
    fi
}
systemd_services_info() {
    if ! command -v systemctl >/dev/null 2>&1; then
        return
    fi
    local findings=0
    while IFS= read -r svc; do
        raw_exec=$(systemctl show "$svc" -p ExecStart --value 2>/dev/null)
        [[ -z "$raw_exec" ]] && continue

        exec_path=$(printf '%s\n' "$raw_exec" \
            | tr ' ' '\n' \
            | grep '^path=' \
            | head -n1 \
            | cut -d= -f2)

        [[ -z "$exec_path" ]] && continue
        [[ "$exec_path" != /* ]] && continue
        if [[ "$exec_path" == /usr/bin/* ||
              "$exec_path" == /bin/* ||
              "$exec_path" == /usr/sbin/* ||
              "$exec_path" == /usr/lib/* ||
              "$exec_path" == /usr/libexec/* ||
              "$exec_path" == /lib/* ||
              "$exec_path" == /sbin/* ]]; then
            continue
        fi

        print_finding "Service $svc runs non-standard binary: $exec_path"
        ((findings++))

    done < <(systemctl list-units --type=service --no-legend | awk '{print $1}')

    if (( findings == 0 )); then
        echo "No non-standard service executables detected.\n"
    fi
}

files_owned_root(){
    set +u
    current_user="$(id -un 2>/dev/null || true)"
    group_list=$(id -Gn 2>/dev/null || true)
    set -u

    if [[ -z "${group_list:-}" ]]; then
        echo "No groups found for current user ${current_user:-unknown}; skipping root-owned find-per-group."
    else
    if command -v timeout >/dev/null 2>&1; then
        timeout_bin="timeout"
        timeout_arg="60s"
    else
        timeout_bin=""
        timeout_arg=""
    fi
    IFS=' ' read -r -a groups_arr <<< "$group_list"
    for grp in "${groups_arr[@]}"; do
        if ! getent group -- "$grp" >/dev/null 2>&1; then
            echo "Skipping group '$grp' (not present in /etc/group or LDAP)."
            continue
        fi
        echo "find root-owned, group $grp, with group r/w/x (/proc NOT scanned!)"
        if [[ -n "$timeout_bin" ]]; then
            find_cmd=( "$timeout_bin" "$timeout_arg" find / -path /proc -prune -o \( -type f -o -type d \) -user root -group "$grp" \( -perm -g=w -o -perm -g=r -o -perm -g=x \) -ls )
        else
            find_cmd=( find / -path /proc -prune -o \( -type f -o -type d \) -user root -group "$grp" \( -perm -g=w -o -perm -g=r -o -perm -g=x \) -ls )
        fi
        set +e
        find_out="$("${find_cmd[@]}" 2>/dev/null || true)"
        rc_find=$?
        set -e

        if [[ -n "${find_out:-}" ]]; then
            echo "$find_out"
        else
            if (( rc_find == 124 )); then
                echo "Find: timed out for group '$grp'."
            else
                echo "Find: no entries found for group '$grp', or permission denied."
            fi
        fi
        echo
    done
    fi
}
list_suid(){
    if command -v timeout >/dev/null 2>&1; then
        timeout_bin="timeout"
        timeout_arg="60s"
    else
        timeout_bin=""
        timeout_arg=""
    fi
    set +e
    if [[ -n "$timeout_bin" ]]; then
        "${timeout_bin}" "${timeout_arg}" find / \( -type f -o -type d \) -perm -04000 -ls 2>/dev/null || true
        rc_suid=$?
    else
        find / \( -type f -o -type d \) -perm -04000 -ls 2>/dev/null || true
        rc_suid=$?
    fi
    set -e
    if (( rc_suid == 124 )); then
        echo "SUID find: timed out (timeout reached)."
    fi
    echo
}
list_sgid(){
    if command -v timeout >/dev/null 2>&1; then
        timeout_bin="timeout"
        timeout_arg="60s"
    else
        timeout_bin=""
        timeout_arg=""
    fi
    set +e
    if [[ -n "$timeout_bin" ]]; then
        "${timeout_bin}" "${timeout_arg}" find / \( -type f -o -type d \) -perm -02000 -ls 2>/dev/null || true
        rc_sgid=$?
    else
        find / \( -type f -o -type d \) -perm -02000 -ls 2>/dev/null || true
        rc_sgid=$?
    fi
    set -e
    if (( rc_sgid == 124 )); then
        echo "SGID find: timed out (timeout reached)."
    fi
    echo
}
print_section "BASIC SYSTEM CONTEXT"
print_subsection "id"
run_cmd id
print_subsection "uname -a"
run_cmd uname -a
print_subsection "env"
run_cmd env
ansi_reset
print_subsection "ls -la "$HOME"/"
run_cmd ls -la "$HOME"/
print_section "PRIVILEGE & IDENTITY"
print_subsection "sudo -V"
run_cmd sudo -V
print_subsection "don't forget to run sudo -l"
print_section "EXECUTION ENVIRONMENT"
print_subsection "Available tools (categorized)"
check_tools
print_subsection "Custom systemd units (/etc/systemd/system)"
systemd_custom_units
print_subsection "Global shell initialization (/etc/profile.d)"
profile_d_info
print_section "NETWORKING"
print_subsection "ip addr or ifconfig -a"
ip_info
print_subsection "cat /etc/hosts"
hosts_info
print_subsection "cat /etc/resolv.conf"
resolv_info
print_subsection "netstat -lntup or ss -lntup"
netstat_info
print_section "FILESYSTEM & STORAGE"
print_subsection "lsblk"
lsblk_info
print_subsection "findmnt"
mount_info
print_subsection "cat /etc/exports (NFS exports)"
exports_info
print_subsection "ls -la /var/www/"
run_cmd ls -la /var/www/ || true
print_subsection "ls -la /opt/"
run_cmd ls -la /opt/ || true
print_section "USERS ENUMERATION"
enumerate_home_users
print_section "SCHEDULED TASKS & SERVICES"
print_subsection "cat /etc/crontab"
crontab_info
print_subsection "systemctl (print only suspicious)"
systemd_services_info
print_section "PERMISSION SURFACES"
print_subsection "Find for files owned by root and group = each group of the invoking user"
files_owned_root
print_subsection "find files/dirs with SUID bit set (perm 04000)"
list_suid
print_subsection "find files/dirs with SGID bit set (perm 02000)"
list_sgid
