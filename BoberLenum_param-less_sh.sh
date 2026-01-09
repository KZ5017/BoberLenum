#!/usr/bin/env sh
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
    output=$("$@" 2>&1)
    rc=$?
    set -e
    printf '%s\n' "$output"
    if [ "$rc" -ne 0 ]; then
        printf 'Exit code: %s\n' "$rc"
    fi
    echo
}
ansi_reset() {
  printf "\033[0m"
}
check_tools() {
    TOOL_CATEGORIES="
wget Network
curl Network
ftp Network
tftp Network
scp Network
sftp Network
ssh Network
telnet Network
nc Network
ncat Network
socat Network
openssl Network
python Interpreter
python2 Interpreter
python3 Interpreter
pip Interpreter
pip3 Interpreter
perl Interpreter
ruby Interpreter
php Interpreter
node Interpreter
npm Interpreter
lua Interpreter
java Interpreter
javac Interpreter
gcc Compiler
cc Compiler
clang Compiler
make Compiler
ld Compiler
objdump Compiler
objcopy Compiler
strip Compiler
find LOLBins
tar LOLBins
zip LOLBins
unzip LOLBins
rsync LOLBins
awk LOLBins
sed LOLBins
less LOLBins
more LOLBins
nano LOLBins
vim LOLBins
vi LOLBins
env LOLBins
timeout LOLBins
docker Container
docker-compose Container
podman Container
kubectl Container
crictl Container
ctr Container
ip Recon
ss Recon
netstat Recon
arp Recon
arping Recon
route Recon
ping Recon
traceroute Recon
nmap Recon
strace Debug
ltrace Debug
ps Debug
pstree Debug
top Debug
htop Debug
watch Debug
7z Archive
7za Archive
gzip Archive
gunzip Archive
xz Archive
lzma Archive
base64 Archive
sudo Privilege
su Privilege
passwd Privilege
newgrp Privilege
chsh Privilege
"

    TMPDIR="/tmp/check_tools.$$"
    mkdir -p "$TMPDIR"

    for cat in Network Interpreter Compiler LOLBins Container Recon Debug Archive Privilege; do
        : > "$TMPDIR/$cat"
    done

    while read tool cat; do
        [ -z "$tool" ] && continue
        if command -v "$tool" >/dev/null 2>&1; then
            echo "$tool" >> "$TMPDIR/$cat"
        fi
    done <<EOF
$TOOL_CATEGORIES
EOF

    for cat in Network Interpreter Compiler LOLBins Container Recon Debug Archive Privilege; do
        if [ -s "$TMPDIR/$cat" ]; then
            print_sub_subsection "$cat"
            while read t; do
                printf "  %s\n" "$t"
            done < "$TMPDIR/$cat"
            echo
        fi
    done
    rm -rf "$TMPDIR"
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
    findings=0
    if [ -d /etc/profile.d ]; then
        ls -la /etc/profile.d
        echo
    else
        echo "-- /etc/profile.d missing --"
        echo
        return
    fi
}
show_user_info() {
    user="$1"
    pw_entry="$(getent passwd "$user" 2>/dev/null)"
    rc_pw=$?

    if [ "$rc_pw" -eq 0 ] && [ -n "$pw_entry" ]; then
        IFS=':' read uname passwd uid gid gecos home shell <<EOF
$pw_entry
EOF
        [ -n "$uname" ] || uname="$user"
        [ -n "$uid" ]   || uid="?"
        [ -n "$gid" ]   || gid="?"
        [ -n "$home" ]  || home="/nonexistent"
        [ -n "$shell" ] || shell="/bin/sh"

        print_sub_subsection "Username: $uname"
        echo "UID: $uid"
        echo "GID: $gid"
        echo "Home: $home"
        echo "Shell: $shell"

        if [ -n "$gecos" ]; then
            echo "GECOS: $gecos"
        fi
    else
        echo "No passwd entry found for $user"
        home="/nonexistent"
    fi
    id_out="$(id "$user" 2>&1)"
    rc_id=$?
    if [ "$rc_id" -eq 0 ]; then
        echo "id: $id_out"
    else
        echo "id: (could not retrieve) $id_out"
    fi
    if command -v lastlog >/dev/null 2>&1; then
        lastlog_out="$(lastlog -u "$user" 2>&1)"
        rc_ll=$?
        if [ "$rc_ll" -eq 0 ] && [ -n "$lastlog_out" ]; then
            echo "Last login:"
            printf '%s\n' "$lastlog_out" | sed -n '2,$p'
        else
            echo "Last login: (no record or cannot access) $lastlog_out"
        fi
    else
        echo "Last login: lastlog not available on system"
    fi
    if [ -n "$home" ] && [ -d "$home" ]; then
        stat_out="$(stat -c 'Owner: %U, Group: %G, Perm: %a (%A), Modified: %y' "$home" 2>&1)"
        rc_stat=$?
        if [ "$rc_stat" -eq 0 ]; then
            echo "Home dir: $stat_out"
        else
            echo "Home dir: (stat failed) $stat_out"
        fi

        if [ -d "$home/.ssh" ]; then
            print_finding ".ssh directory exists"
            if [ -f "$home/.ssh/authorized_keys" ]; then
                print_finding "authorized_keys: present"
            else
                echo "authorized_keys: not present"
            fi
        else
            echo ".ssh directory: not present"
        fi

        for hist in .bash_history .zsh_history .profile; do
            if [ -f "$home/$hist" ]; then
                hstat="$(stat -c '%s bytes, modified %y' "$home/$hist" 2>/dev/null || echo "stat failed")"
                print_finding "History file $hist: $hstat"
            fi
        done
    else
        echo "Home directory: not present or not accessible"
    fi
    emails=""
    if [ -n "$gecos" ]; then
        printf '%s\n' "$gecos" |
        grep -Eo '[A-Za-z0-9._%+-]\+@[A-Za-z0-9.-]\+\.[A-Za-z]\{2,\}' 2>/dev/null |
        while IFS= read -r e; do
            emails="$emails$e"
        done
    fi
    for spool in "/var/mail/$user" "/var/spool/mail/$user"; do
        if [ -r "$spool" ]; then
            head -n 50 "$spool" 2>/dev/null |
            grep -Eo '[A-Za-z0-9._%+-]\+@[A-Za-z0-9.-]\+\.[A-Za-z]\{2,\}' |
            while IFS= read -r e; do
                emails="$emails$e"
            done
        fi
    done
    uniq_emails=""
    echo "$emails" | while IFS= read -r e; do
        [ -z "$e" ] && continue
        clean="$(printf '%s' "$e" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        echo "$uniq_emails" | grep -qx "$clean" 2>/dev/null || {
            uniq_emails="$uniq_emails$clean"
        }
    done

    if [ -n "$uniq_emails" ]; then
        print_finding "Possible email addresses related to $user:"
        echo "$uniq_emails"
    else
        echo "No email addresses found for $user (GECOS/spool checked)."
    fi
    crontab_out="$(crontab -l -u "$user" 2>&1)"
    rc_cron=$?
    if [ "$rc_cron" -eq 0 ]; then
        print_finding "Crontab entries for $user:"
        printf '%s\n' "$crontab_out"
    else
        echo "Crontab: not available via crontab -l (message: $crontab_out)"
        if [ -r "/var/spool/cron/crontabs/$user" ]; then
            print_finding "Spool /var/spool/cron/crontabs/$user:"
            cat "/var/spool/cron/crontabs/$user"
        elif [ -r "/var/spool/cron/$user" ]; then
            print_finding "Spool /var/spool/cron/$user:"
            cat "/var/spool/cron/$user"
        else
            echo "No spool file readable for $user."
        fi
    fi
    current_user="$(id -un 2>/dev/null || echo "")"
    if [ "$current_user" = "$user" ]; then
        echo "Find: skipped for $user (invoking user)."
        echo
        return
    fi
    print_subsection_warn "find owned readable/writable/executable by $user (/proc NOT scanned!)"
    if command -v timeout >/dev/null 2>&1; then
        find_cmd="timeout 60s find / -path /proc -prune -o \( -type f -o -type d \) -user $user -ls"
    else
        find_cmd="find / -path /proc -prune -o \( -type f -o -type d \) -user $user -ls"
    fi
    find_out="$(sh -c "$find_cmd" 2>/dev/null)"
    rc_find=$?

    if [ -n "$find_out" ]; then
        echo "$find_out"
    else
        if [ "$rc_find" -eq 124 ]; then
            echo "Find: timed out."
        else
            echo "Find: no readable/writable/executable entries found or permission denied."
        fi
    fi
    echo
}
enumerate_home_users() {
    print_subsection "ls -la /home/"
    set +e
    ls -la /home/ 2>&1
    rc_ls=$?
    set -e
    if [ "$rc_ls" -ne 0 ]; then
        echo "Note: ls -la /home/ returned exit code $rc_ls"
    fi
    echo
    print_subsection "list of users with home directory"
    for entry in /home/*; do
        if [ -d "$entry" ]; then
            user=$(basename "$entry")
            set +e
            show_user_info "$user"
            rc_show=$?
            set -e
            if [ "$rc_show" -ne 0 ]; then
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
hosts_info() {
    if [ -r /etc/hosts ]; then
        run_cmd cat /etc/hosts
    else
        echo "-- /etc/hosts (unreadable or missing) --"
        echo "/etc/hosts not readable or does not exist"
        echo
    fi
}
resolv_info() {
    if [ -e /etc/resolv.conf ]; then
        if [ -L /etc/resolv.conf ]; then
            run_cmd ls -l /etc/resolv.conf
        fi
        if [ -r /etc/resolv.conf ]; then
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
    root_dev="$(findmnt -n -o SOURCE / 2>/dev/null | sed 's|/dev/||')"
    lsblk -n -o NAME,SIZE,FSTYPE,MOUNTPOINT | while IFS= read -r line; do
        name=$(printf '%s\n' "$line" | awk '{print $1}')
        mountpoint=$(printf '%s\n' "$line" | awk '{print $4}')
        [ "$name" = "NAME" ] && continue
        if [ -n "$mountpoint" ] && [ "$mountpoint" != "/" ]; then
            print_finding "Additional block device mounted: /dev/$name -> $mountpoint"
        fi
    done
    echo
}
mount_info() {
    if ! command -v findmnt >/dev/null 2>&1; then
        run_cmd mount
        return
    fi
    findmnt -ro TARGET,SOURCE,SIZE,FSTYPE,OPTIONS
    echo
    findings=0
    findmnt -ro TARGET,SOURCE,SIZE,FSTYPE | while IFS= read -r line; do
        target=$(printf '%s\n' "$line" | awk '{print $1}')
        source=$(printf '%s\n' "$line" | awk '{print $2}')
        size=$(printf '%s\n' "$line" | awk '{print $3}')
        fstype=$(printf '%s\n' "$line" | awk '{print $4}')
        case "$target" in
            /|/boot|/boot/*|/proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/run|/run/*|/usr|/usr/*|/lib|/lib/*|/var|/var/*)
                continue
                ;;
        esac
        case "$target" in
            /mnt*|/media*|/opt*|/srv*|/tmp*|/home*|/data*|/backup*|/exports*|/shared*)
                print_finding "Non-standard mount detected: $target ($fstype, $size) <- $source"
                findings=1
                ;;
        esac
    done
    echo
}
exports_info() {
    if [ ! -e /etc/exports ]; then
        echo "-- /etc/exports (missing) --"
        echo "/etc/exports does not exist"
        echo
        return
    fi
    if [ ! -r /etc/exports ]; then
        echo "-- /etc/exports (unreadable) --"
        echo "/etc/exports exists but is not readable"
        echo
        return
    fi
    run_cmd cat /etc/exports
    findings=0
    if grep -qE 'no_root_squash' /etc/exports 2>/dev/null; then
        print_finding "NFS export uses no_root_squash (root privilege passthrough)"
        findings=1
    fi
    if grep -qE '\(.*rw' /etc/exports 2>/dev/null; then
        print_finding "Writable NFS export detected (rw)"
        findings=1
    fi
    if grep -qE '(^|[[:space:]])\*' /etc/exports 2>/dev/null; then
        print_finding "NFS export allows all hosts (*)"
        findings=1
    fi
    if grep -qE 'insecure' /etc/exports 2>/dev/null; then
        print_finding "NFS export allows insecure ports"
        findings=1
    fi
    if grep -qE 'sync' /etc/exports 2>/dev/null; then
        print_finding "NFS export uses sync option (performance hint, review context)"
        findings=1
    fi
    if [ "$findings" -eq 0 ]; then
        :
    fi
    echo
}
crontab_info() {
    if [ -r /etc/crontab ]; then
        run_cmd cat /etc/crontab
    else
        echo "-- /etc/crontab (unreadable or missing) --"
        echo "/etc/crontab not readable or does not exist"
        echo
    fi
    user_cron="$(crontab -l 2>/dev/null || true)"
    echo "-- User crontab --"
    if [ -n "$user_cron" ]; then
        printf '%s\n' "$user_cron"
        echo
        printf '%s\n' "$user_cron" | while IFS= read -r line; do
            case "$line" in
                ""|\#*) continue ;;
            esac
            cmd=$(printf '%s\n' "$line" | awk '{for (i=6; i<=NF; i++) printf $i " ";}')
            case "$cmd" in
                *"/usr/bin/"*|*"/bin/"*|*"/usr/sbin/"*)
                    ;;
                *)
                    print_finding "Cron job executes non-standard path: $cmd"
                    ;;
            esac
        done
    else
        echo "No user crontab entries"
        echo
    fi
}
systemd_services_info() {
    if ! command -v systemctl >/dev/null 2>&1; then
        return
    fi
    findings=0
    systemctl list-units --type=service --no-legend | awk '{print $1}' |
    while IFS= read -r svc; do
        raw_exec=$(systemctl show "$svc" -p ExecStart --value 2>/dev/null)
        [ -z "$raw_exec" ] && continue

        exec_path=$(printf '%s\n' "$raw_exec" | tr ' ' '\n' | grep '^path=' | head -n1 | cut -d= -f2)
        [ -z "$exec_path" ] && continue
        case "$exec_path" in /*) ;; *) continue ;; esac

        case "$exec_path" in
            /usr/bin/*|/bin/*|/usr/sbin/*|/usr/lib/*|/usr/libexec/*|/lib/*|/sbin/*)
                continue
                ;;
        esac
        print_finding "Service $svc runs non-standard binary: $exec_path"
        findings=$(expr "$findings" + 1)
    done
    if [ "$findings" -eq 0 ]; then
        echo "No non-standard service executables detected."
        echo
    fi
}
files_owned_root() {
    set +u
    current_user="$(id -un 2>/dev/null || true)"
    group_list="$(id -Gn 2>/dev/null || true)"
    set -u

    if [ -z "$group_list" ]; then
        echo "No groups found for current user ${current_user:-unknown}; skipping root-owned find-per-group."
        return
    fi
    if command -v timeout >/dev/null 2>&1; then
        timeout_bin="timeout"
        timeout_arg="60s"
    else
        timeout_bin=""
        timeout_arg=""
    fi
    echo "$group_list" | tr ' ' '\n' |
    while IFS= read -r grp; do
        [ -z "$grp" ] && continue

        if ! getent group "$grp" >/dev/null 2>&1; then
            echo "Skipping group '$grp' (not present in /etc/group or LDAP)."
            continue
        fi
        echo "find root-owned, group $grp, with group r/w/x (/proc NOT scanned!)"

        if [ -n "$timeout_bin" ]; then
            cmd="$timeout_bin $timeout_arg find / -path /proc -prune -o \( -type f -o -type d \) -user root -group $grp \( -perm -g=w -o -perm -g=r -o -perm -g=x \) -ls"
        else
            cmd="find / -path /proc -prune -o \( -type f -o -type d \) -user root -group $grp \( -perm -g=w -o -perm -g=r -o -perm -g=x \) -ls"
        fi
        set +e
        find_out=$(sh -c "$cmd" 2>/dev/null)
        rc_find=$?
        set -e
        if [ -n "$find_out" ]; then
            echo "$find_out"
        else
            if [ "$rc_find" -eq 124 ]; then
                echo "Find: timed out for group '$grp'."
            else
                echo "Find: no entries found for group '$grp', or permission denied."
            fi
        fi
        echo
    done
}
list_suid() {
    if command -v timeout >/dev/null 2>&1; then
        timeout_bin="timeout"
        timeout_arg="60s"
    else
        timeout_bin=""
        timeout_arg=""
    fi
    set +e
    if [ -n "$timeout_bin" ]; then
        $timeout_bin "$timeout_arg" find / \( -type f -o -type d \) -perm -04000 -ls 2>/dev/null
        rc_suid=$?
    else
        find / \( -type f -o -type d \) -perm -04000 -ls 2>/dev/null
        rc_suid=$?
    fi
    set -e
    if [ "$rc_suid" -eq 124 ]; then
        echo "SUID find: timed out (timeout reached)."
    fi
    echo
}
list_sgid() {
    if command -v timeout >/dev/null 2>&1; then
        timeout_bin="timeout"
        timeout_arg="60s"
    else
        timeout_bin=""
        timeout_arg=""
    fi
    set +e
    if [ -n "$timeout_bin" ]; then
        $timeout_bin "$timeout_arg" find / \( -type f -o -type d \) -perm -02000 -ls 2>/dev/null
        rc_sgid=$?
    else
        find / \( -type f -o -type d \) -perm -02000 -ls 2>/dev/null
        rc_sgid=$?
    fi
    set -e
    if [ "$rc_sgid" -eq 124 ]; then
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
