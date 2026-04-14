#!/usr/bin/env sh
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

# This is a best-effort enumeration script: do not abort on missing tools,
# unreadable files, unset environment variables, or non-zero probe results.
set +e
set +u

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
  title="$1"
  echo
  printf '%b\n' "${BLUE}${BOLD}===============================================================================${RESET}"
  printf '%b[ %s ]%b\n' "${BLUE}${BOLD}" "$title" "$RESET"
  printf '%b\n' "${BLUE}${BOLD}===============================================================================${RESET}"
  echo
}

print_subsection() {
  title="$1"
  printf "${CYAN}${BOLD}=== %s ===${RESET}\n" "$title"
  echo
}

print_sub_subsection() {
  title="$1"
  printf "${GREEN}${BOLD}[ %s ]${RESET}\n" "$title"
  echo
}

print_finding() {
  msg="$1"
  printf "${RED}${BOLD}>>> %s${RESET}\n" "$msg"
}

run_cmd() {
    set +e
    output=$("$@" 2>&1)
    rc=$?
    set +e
    printf '%s\n' "$output"
    if [ "$rc" -ne 0 ]; then
        printf 'Exit code: %s\n' "$rc"
    fi
    echo
}

ansi_reset() {
  printf "\033[0m"
}

run_sudo() {
    if command -v sudo >/dev/null 2>&1; then
        run_cmd sudo -V
        print_subsection "sudo -n -l (non-interactive)"
        set +e
        sudo_list="$(sudo -n -l 2>&1)"
        sudo_list_rc=$?
        set +e
        printf '%s\n' "$sudo_list"
        if [ "$sudo_list_rc" -eq 0 ]; then
            print_finding "sudo -n -l succeeded; review allowed commands for privesc paths"
        else
            echo "sudo -n -l failed or requires a password."
        fi
        echo
    else
        echo "sudo not available on this system"
        echo
    fi
}

path_hijack_info() {
    path_value=${PATH:-}

    echo "PATH: ${path_value:-unset}"
    if [ -z "$path_value" ]; then
        echo "PATH is unset or empty."
        echo
        return 0
    fi

    case "$path_value" in
        :*|*::*|*:)
            print_finding "PATH contains an empty element (current directory may be searched)"
            ;;
    esac

    old_ifs=$IFS
    IFS=:
    for dir in $path_value; do
        IFS=$old_ifs
        [ -n "$dir" ] || continue

        case "$dir" in
            /*) ;;
            *)
                print_finding "PATH contains a relative directory: $dir"
                ;;
        esac

        if [ -d "$dir" ]; then
            ls -ld "$dir" 2>&1
            if [ -w "$dir" ]; then
                print_finding "Writable PATH directory: $dir"
            fi
        else
            echo "PATH directory missing or not a directory: $dir"
        fi
        IFS=:
    done
    IFS=$old_ifs
    echo

    return 0
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

    while IFS=' ' read -r tool cat; do
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
            while IFS= read -r t; do
                printf "  %s\n" "$t"
            done < "$TMPDIR/$cat"
            echo
        fi
    done

    rm -rf "$TMPDIR"
}

systemd_custom_units() {
    if ls /etc/systemd/system/*.service >/dev/null 2>&1; then
        ls -la /etc/systemd/system/*.service
        echo
    else
        echo "-- No custom .service files found --"
        echo
    fi
    echo "Review hint: inspect custom .service files for ExecStart, User, Group, WorkingDirectory, Environment, and EnvironmentFile."
    echo
}

profile_d_info() {
    if [ -d /etc/profile.d ]; then
        ls -la /etc/profile.d
        echo
    else
        echo "-- /etc/profile.d missing --"
        echo
        return
    fi
    echo "Review hint: inspect /etc/profile.d scripts for writable files, PATH changes, sourced files, and exported secrets."
    echo
}

show_user_info() {
    user="$1"

    pw_entry="$(getent passwd "$user" 2>/dev/null || true)"

    if [ -n "$pw_entry" ]; then
        IFS=':' read -r uname _passwd uid gid gecos home shell <<EOF
$pw_entry
EOF
        uname=${uname:-$user}
        uid=${uid:-?}
        gid=${gid:-?}
        home=${home:-/nonexistent}
        shell=${shell:-/bin/sh}
        gecos=${gecos:-}

        print_sub_subsection "Username: $uname"
        echo "UID: $uid"
        echo "GID: $gid"
        echo "Home: $home"
        echo "Shell: $shell"

        [ -n "$gecos" ] && echo "GECOS: $gecos"
    else
        echo "No passwd entry found for $user"
        home="/nonexistent"
        gecos=""
    fi

    id_out="$(id "$user" 2>&1 || true)"
    echo "id: $id_out"

    if command -v lastlog >/dev/null 2>&1; then
        lastlog_out="$(lastlog -u "$user" 2>&1 || true)"
        if [ -n "$lastlog_out" ]; then
            echo "Last login:"
            printf '%s\n' "$lastlog_out" | sed -n '2,$p'
        else
            echo "Last login: (no record or cannot access)"
        fi
    else
        echo "Last login: lastlog not available on system"
    fi

    if [ -n "$home" ] && [ -d "$home" ]; then
        stat_out="$(stat -c 'Owner: %U, Group: %G, Perm: %a (%A), Modified: %y' "$home" 2>&1 || true)"
        echo "Home dir: $stat_out"

        if [ -d "$home/.ssh" ]; then
            print_finding ".ssh directory exists"
            [ -f "$home/.ssh/authorized_keys" ] \
                && print_finding "authorized_keys: present" \
                || echo "authorized_keys: not present"
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
        for e in $(printf '%s\n' "$gecos" |
            grep -Eo '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' 2>/dev/null); do
            emails="$emails
$e"
        done
    fi

    for spool in "/var/mail/$user" "/var/spool/mail/$user"; do
        if [ -r "$spool" ]; then
            for e in $(head -n 50 "$spool" 2>/dev/null |
                grep -Eo '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'); do
                emails="$emails
$e"
            done
        fi
    done

    uniq_emails=""
    for e in $emails; do
        echo "$uniq_emails" | grep -qx "$e" 2>/dev/null || uniq_emails="$uniq_emails
$e"
    done

    if [ -n "$uniq_emails" ]; then
        print_finding "Possible email addresses related to $user:"
        printf '%s\n' "$uniq_emails"
    else
        echo "No email addresses found for $user (GECOS/spool checked)."
    fi

    crontab_out="$(crontab -l -u "$user" 2>&1 || true)"
    if [ -n "$crontab_out" ]; then
        print_finding "Crontab entries for $user:"
        printf '%s\n' "$crontab_out"
    else
        echo "Crontab: not available via crontab -l"
    fi

    current_user="$(id -un 2>/dev/null || echo "")"
    if [ "$current_user" = "$user" ]; then
        echo "Find: skipped for $user (invoking user)."
        echo
        return
    fi

    echo "find owned files by $user (/proc NOT scanned!)"
    if command -v timeout >/dev/null 2>&1; then
        find_cmd="timeout 60s find / -path /proc -prune -o -user \"$user\" -ls"
    else
        find_cmd="find / -path /proc -prune -o -user \"$user\" -ls"
    fi

    find_out="$(sh -c "$find_cmd" 2>/dev/null || true)"
    [ -n "$find_out" ] && printf '%s\n' "$find_out" || echo "Find: no results or timed out"
    echo
}

enumerate_home_users() {
    print_subsection "ls -la /home/"
    ls -la /home/ 2>&1 || true
    echo

    print_subsection "list of users with home directory"
    for entry in /home/*; do
        [ -d "$entry" ] || continue
        user=$(basename "$entry")
        show_user_info "$user" || echo "Warning: show_user_info failed for $user"
    done
}

ip_info() {
    if command -v ip >/dev/null 2>&1; then
        run_cmd ip addr
    elif command -v ifconfig >/dev/null 2>&1; then
        run_cmd ifconfig -a
    else
        echo "-- ip/ifconfig not found --"
        echo "Neither ip nor ifconfig is available on this system."
        echo
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
        if ls -l /etc/resolv.conf >/dev/null 2>&1; then
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

netstat_info() {
    if command -v netstat >/dev/null 2>&1; then
        run_cmd netstat -lntup
    elif command -v ss >/dev/null 2>&1; then
        run_cmd ss -lntup
    else
        echo "-- netstat/ss not found --"
        echo "Neither netstat nor ss is available on this system."
        echo
    fi
}

lsblk_info() {
    if ! command -v lsblk >/dev/null 2>&1; then
        return
    fi

    lsblk -o NAME,MAJ:MIN,SIZE,FSTYPE,MOUNTPOINT
    printf '\n'

    root_dev=""
    if command -v findmnt >/dev/null 2>&1; then
        root_dev=$(findmnt -n -o SOURCE / 2>/dev/null | sed 's|^/dev/||')
    fi

    lsblk -n -P -o NAME,SIZE,FSTYPE,MOUNTPOINT | {
        # shellcheck disable=SC2094
        while IFS= read -r line; do
            name=$(echo "$line" | sed -n 's/.*NAME="\([^"]*\)".*/\1/p')
            mountpoint=$(echo "$line" | sed -n 's/.*MOUNTPOINT="\([^"]*\)".*/\1/p')

            [ -z "$name" ] && continue
            [ -n "$root_dev" ] && [ "$name" = "$root_dev" ] && continue

            if [ -n "$mountpoint" ] && [ "$mountpoint" != "/" ]; then
                print_finding "Additional block device mounted: /dev/$name -> $mountpoint"
            fi
        done
    }

    printf '\n'
    return 0
}

mount_info() {
    if ! command -v findmnt >/dev/null 2>&1; then
        run_cmd mount
        return
    fi

    findmnt -lo TARGET,SOURCE,SIZE,FSTYPE,OPTIONS
    echo

    findmnt -ro TARGET,SOURCE,SIZE,FSTYPE,OPTIONS | {
        while IFS= read -r line; do
            target=$(echo "$line" | awk '{print $1}')
            source=$(echo "$line" | awk '{print $2}')
            size=$(echo "$line" | awk '{print $3}')
            fstype=$(echo "$line" | awk '{print $4}')
            options=$(echo "$line" | awk '{print $5}')
            interesting_mount=0
            shared_mount=0
            hardening_mount=0

            case "$target" in
                /|/boot|/boot/*|/proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/run|/run/*|/usr|/usr/*|/lib|/lib/*|/var|/var/*)
                    continue
                    ;;
            esac

            case "$target" in
                /mnt*|/media*|/opt*|/srv*|/tmp*|/home*|/data*|/backup*|/exports*|/shared*)
                    print_finding "Non-standard mount detected: $target ($fstype, $size) <- $source"
                    interesting_mount=1
                    ;;
            esac

            case "$target" in
                /tmp*|/mnt*|/media*|/data*|/backup*|/exports*|/shared*)
                    hardening_mount=1
                    ;;
            esac

            case "$fstype" in
                nfs|nfs4|cifs|smb3|smbfs|fuse.sshfs)
                    print_finding "Network/shared mount detected: $target ($fstype, $size, $options) <- $source"
                    interesting_mount=1
                    shared_mount=1
                    hardening_mount=1
                    ;;
            esac

            case ",$options," in
                *,rw,*)
                    if [ "$interesting_mount" -eq 1 ] && [ "$hardening_mount" -eq 1 ]; then
                        case ",$options," in
                            *,nosuid,*) ;;
                            *)
                                print_finding "Writable interesting mount lacks nosuid: $target ($fstype, $options)"
                                ;;
                        esac

                        case ",$options," in
                            *,nodev,*) ;;
                            *)
                                print_finding "Writable interesting mount lacks nodev: $target ($fstype, $options)"
                                ;;
                        esac

                        case "$target" in
                            /tmp*|/mnt*|/media*|/data*|/backup*|/exports*|/shared*)
                                case ",$options," in
                                    *,noexec,*) ;;
                                    *)
                                        print_finding "Writable temporary/shared mount lacks noexec: $target ($fstype, $options)"
                                        ;;
                                esac
                                ;;
                        esac
                    fi

                    if [ "$shared_mount" -eq 1 ]; then
                        print_finding "Read-write network/shared mount: review server-side export policy and trust boundary: $target <- $source"
                    fi
                    ;;
            esac
        done
    }
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

    exports_active="$(grep -Ev '^[[:space:]]*(#|$)' /etc/exports 2>/dev/null || true)"

    if [ -z "$exports_active" ]; then
        echo "No active NFS export entries found in /etc/exports."
        echo
        return
    fi

    echo "-- Active /etc/exports entries reviewed for risky options --"
    printf '%s\n' "$exports_active"
    echo

    if printf '%s\n' "$exports_active" | grep 'no_root_squash' >/dev/null 2>&1; then
        print_finding "NFS export uses no_root_squash (root privilege passthrough)"
    fi

    if printf '%s\n' "$exports_active" | grep -E '(^|[,([:space:]])rw([,),[:space:]]|$)' >/dev/null 2>&1; then
        print_finding "Writable NFS export detected (rw)"
    fi

    if printf '%s\n' "$exports_active" | grep -E '[[:space:]]\*([[:space:]]|\(|$)' >/dev/null 2>&1; then
        print_finding "NFS export allows all hosts (*)"
    fi

    if printf '%s\n' "$exports_active" | grep 'insecure' >/dev/null 2>&1; then
        print_finding "NFS export allows insecure ports"
    fi

    if printf '%s\n' "$exports_active" | grep -E '(^|[,([:space:]])sync([,),[:space:]]|$)' >/dev/null 2>&1; then
        print_finding "NFS export uses sync option (performance hint, review context)"
    fi

    printf '%s\n' "$exports_active" | while IFS= read -r export_line; do
        if printf '%s\n' "$export_line" | grep -E '(^|[,([:space:]])rw([,),[:space:]]|$)' >/dev/null 2>&1 &&
            printf '%s\n' "$export_line" | grep 'no_root_squash' >/dev/null 2>&1; then
            print_finding "High-risk NFS export combo (rw + no_root_squash): $export_line"
        fi

        if printf '%s\n' "$export_line" | grep -E '(^|[,([:space:]])rw([,),[:space:]]|$)' >/dev/null 2>&1 &&
            printf '%s\n' "$export_line" | grep -E '[[:space:]]\*([[:space:]]|\(|$)' >/dev/null 2>&1; then
            print_finding "Broad writable NFS export candidate (rw + wildcard host): $export_line"
        fi
    done

    if ! printf '%s\n' "$exports_active" | grep -E 'root_squash|no_root_squash|all_squash' >/dev/null 2>&1; then
        echo "Review hint: no explicit squash option found in active exports; verify distro defaults and export intent."
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
            cmd=$(printf '%s\n' "$line" | awk '{for (i=6; i<=NF; i++) printf "%s ", $i}')
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
        echo "systemctl not available on this system."
        echo
        return 0
    fi

    findings=0
    services_tmp="/tmp/boberlenum_services.$$"

    systemctl list-units --type=service --no-legend 2>/dev/null | awk '{print $1}' > "$services_tmp" || true

    while IFS= read -r svc; do
        raw_exec=$(systemctl show "$svc" -p ExecStart --value 2>/dev/null)
        [ -z "$raw_exec" ] && continue

        exec_path=$(printf '%s\n' "$raw_exec" | tr ' ' '\n' | sed -n 's/^path=//p' | head -n1)
        [ -z "$exec_path" ] && continue

        case "$exec_path" in
            /*) ;;
            *) continue ;;
        esac

        case "$exec_path" in
            /usr/bin/*|/bin/*|/usr/sbin/*|/usr/lib/*|/usr/libexec/*|/lib/*|/sbin/*)
                continue
                ;;
        esac

        print_finding "Service $svc runs non-standard binary: $exec_path"
        findings=$((findings + 1))
    done < "$services_tmp"

    rm -f "$services_tmp"

    if [ "$findings" -eq 0 ]; then
        echo "No non-standard service executables detected."
        echo
    fi

    return 0
}

scheduled_task_writable_targets() {
    echo
    print_subsection "Writable scheduled task/service targets"

    found=0

    check_writable_target() {
        src="$1"
        target="$2"

        [ -n "$target" ] || return 0

        case "$target" in
            /*) ;;
            *) return 0 ;;
        esac

        if [ -e "$target" ]; then
            if [ -w "$target" ]; then
                found=1
                print_finding "Writable scheduled target from $src: $target"
                ls -la "$target" 2>&1
            fi
        else
            parent_dir=$(dirname "$target" 2>/dev/null || echo "")
            if [ -n "$parent_dir" ] && [ -d "$parent_dir" ] && [ -w "$parent_dir" ]; then
                found=1
                print_finding "Scheduled target missing but parent directory is writable from $src: $target"
                ls -ld "$parent_dir" 2>&1
            fi
        fi

        return 0
    }

    # shellcheck disable=SC2094
    parse_cron_file_for_targets() {
        cron_file="$1"
        [ -r "$cron_file" ] || return 0

        while IFS= read -r line; do
            case "$line" in
                ""|\#*) continue ;;
            esac

            case "$line" in
                *=*) continue ;;
            esac

            cmd=""
            # shellcheck disable=SC2086
            set -- $line
            case "$cron_file" in
                /etc/crontab|/etc/cron.d/*)
                    [ "$#" -ge 7 ] || continue
                    shift 6
                    ;;
                *)
                    [ "$#" -ge 6 ] || continue
                    shift 5
                    ;;
            esac

            cmd="$1"
            case "$cmd" in
                cd|cd\;|/usr/bin/env|env|sudo|su|sh|bash|dash|/bin/sh|/bin/bash|/usr/bin/bash|/usr/bin/sh)
                    shift
                    cmd="$1"
                    ;;
            esac

            case "$cmd" in
                */bin/env)
                    shift
                    cmd="$1"
                    ;;
            esac

            check_writable_target "$cron_file" "$cmd"
        done < "$cron_file"
    }

    if [ -r /etc/crontab ]; then
        parse_cron_file_for_targets /etc/crontab
    fi

    for cron_file in /etc/cron.d/*; do
        [ -f "$cron_file" ] || continue
        parse_cron_file_for_targets "$cron_file"
    done

    set +e
    user_cron_targets="$(crontab -l 2>/dev/null || true)"
    set +e
    if [ -n "$user_cron_targets" ]; then
        user_cron_tmp="/tmp/boberlenum_user_cron.$$"
        printf '%s\n' "$user_cron_targets" > "$user_cron_tmp"
        parse_cron_file_for_targets "$user_cron_tmp"
        rm -f "$user_cron_tmp"
    fi

    if command -v systemctl >/dev/null 2>&1; then
        sched_services_tmp="/tmp/boberlenum_sched_services.$$"
        systemctl list-units --type=service --no-legend 2>/dev/null | awk '{print $1}' > "$sched_services_tmp" || true

        while IFS= read -r svc; do
            [ -n "$svc" ] || continue
            raw_exec=$(systemctl show "$svc" -p ExecStart --value 2>/dev/null)
            [ -n "$raw_exec" ] || continue

            exec_path=$(printf '%s\n' "$raw_exec" | tr ' ' '\n' | sed -n 's/^path=//p' | head -n1)
            [ -n "$exec_path" ] || continue

            check_writable_target "systemd:$svc" "$exec_path"
        done < "$sched_services_tmp"

        rm -f "$sched_services_tmp"
    else
        echo "systemctl not available; systemd ExecStart target checks skipped."
    fi

    if [ "$found" -eq 0 ]; then
        echo "No writable scheduled task/service targets detected by simple heuristic."
    fi
    echo

    return 0
}

files_owned_root() {
    set +u
    current_user="$(id -un 2>/dev/null || true)"
    group_list="$(id -Gn 2>/dev/null || true)"
    set +u

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
        set +e
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

files_writable_other_users() {
    current_uid="$(id -u 2>/dev/null || true)"
    current_user="$(id -un 2>/dev/null || true)"

    if [ -z "$current_uid" ]; then
        echo "Could not determine current UID; skipping writable files owned by other users."
        echo
        return 0
    fi

    case "$current_uid" in
        *[!0-9]*)
            echo "Current UID '$current_uid' is not numeric; skipping writable files owned by other users."
            echo
            return 0
            ;;
    esac

    if command -v timeout >/dev/null 2>&1; then
        timeout_bin="timeout"
        timeout_arg="60s"
    else
        timeout_bin=""
        timeout_arg=""
    fi

    echo "find files/dirs owned by other users but writable by ${current_user:-uid $current_uid} (/proc NOT scanned!)"

    if [ -n "$timeout_bin" ]; then
        cmd="$timeout_bin $timeout_arg find / -path /proc -prune -o \( -type f -o -type d \) ! -user $current_uid -exec sh -c 'for p do [ -w \"\$p\" ] && ls -ld \"\$p\"; done' sh {} +"
    else
        cmd="find / -path /proc -prune -o \( -type f -o -type d \) ! -user $current_uid -exec sh -c 'for p do [ -w \"\$p\" ] && ls -ld \"\$p\"; done' sh {} +"
    fi

    set +e
    writable_out=$(sh -c "$cmd" 2>/dev/null)
    rc_writable=$?
    set +e

    if [ -n "$writable_out" ]; then
        printf '%s\n' "$writable_out"
        echo

        printf '%s\n' "$writable_out" | while IFS= read -r line; do
            case "$line" in
                *" /bin/sh"|*" /bin/bash"|*" /bin/dash"|*" /bin/zsh"|*" /bin/ksh"|*" /usr/bin/sh"|*" /usr/bin/bash"|*" /usr/bin/dash"|*" /usr/bin/zsh"|*" /usr/bin/ksh")
                    print_finding "Potential privesc target: writable shell binary: $line"
                    ;;
                *" /usr/bin/python"*|*" /usr/local/bin/python"*|*" /usr/bin/perl"|*" /usr/bin/ruby"|*" /usr/bin/php"|*" /usr/bin/node"|*" /usr/bin/lua")
                    print_finding "Potential privesc target: writable interpreter: $line"
                    ;;
                *" /bin/su"|*" /usr/bin/su"|*" /usr/bin/sudo"|*" /usr/bin/passwd"|*" /usr/bin/pkexec"|*" /usr/bin/systemctl")
                    print_finding "Potential privesc target: writable privileged/system helper: $line"
                    ;;
                *" /etc/passwd"|*" /etc/shadow"|*" /etc/sudoers"|*" /etc/sudoers.d/"*)
                    print_finding "Potential privesc target: writable account/sudo policy file: $line"
                    ;;
                *" /etc/cron.d/"*|*" /var/spool/cron/crontabs/"*|*" /etc/crontab"|*" /etc/cron."*|*" /var/spool/cron/"*)
                    print_finding "Potential privesc target: writable cron path: $line"
                    ;;
                *" /etc/systemd/system/"*|*" /lib/systemd/system/"*|*" /usr/lib/systemd/system/"*|*" /etc/init.d/"*|*.service)
                    print_finding "Potential privesc target: writable service/init path: $line"
                    ;;
                *" /etc/profile"|*" /etc/profile.d/"*|*" /etc/bash.bashrc"|*" /.profile"|*" /.bashrc"|*" /.bash_profile")
                    print_finding "Potential privesc target: writable shell startup file: $line"
                    ;;
                *.sh|*.py|*.pl|*.rb|*.php|*.js|*.lua)
                    print_finding "Potential privesc target: writable script/source file: $line"
                    ;;
                *" /usr/local/bin/"*|*" /usr/local/sbin/"*|*" /usr/bin/"*|*" /usr/sbin/"*|*" /bin/"*|*" /sbin/"*)
                    print_finding "Potential privesc target: writable PATH binary or directory: $line"
                    ;;
            esac
        done
    else
        if [ "$rc_writable" -eq 124 ]; then
            echo "Find: timed out while checking writable files owned by other users."
        else
            echo "Find: no writable files/dirs owned by other users found, or permission denied."
        fi
    fi
    echo

    return 0
}

list_file_capabilities() {
    if ! command -v getcap >/dev/null 2>&1; then
        echo "getcap not available on this system."
        echo
        return
    fi

    if command -v timeout >/dev/null 2>&1; then
        timeout_bin="timeout"
        timeout_arg="60s"
    else
        timeout_bin=""
        timeout_arg=""
    fi

    echo "Listing file capabilities (getcap -r /) ..."

    set +e
    if [ -n "$timeout_bin" ]; then
        cap_out=$("$timeout_bin" "$timeout_arg" getcap -r / 2>/dev/null)
        rc_cap=$?
    else
        cap_out=$(getcap -r / 2>/dev/null)
        rc_cap=$?
    fi
    set +e

    if [ -n "$cap_out" ]; then
        printf '%s\n' "$cap_out"
        echo

        printf '%s\n' "$cap_out" | while IFS= read -r line; do
            case "$line" in
                *cap_setuid*)
                    print_finding "High-risk capability: cap_setuid (possible UID transition): $line"
                    print_finding "Check GTFOBins/capability abuse for this binary"
                    ;;
                *cap_setgid*)
                    print_finding "High-risk capability: cap_setgid (possible GID transition): $line"
                    print_finding "Check GTFOBins/capability abuse for this binary"
                    ;;
                *cap_dac_read_search*)
                    print_finding "High-risk capability: cap_dac_read_search (may bypass file read/search permissions): $line"
                    ;;
                *cap_dac_override*)
                    print_finding "High-risk capability: cap_dac_override (may bypass file permission checks): $line"
                    ;;
                *cap_sys_admin*)
                    print_finding "High-risk capability: cap_sys_admin (broad kernel/admin surface): $line"
                    ;;
                *cap_chown*)
                    print_finding "Interesting capability: cap_chown (ownership changes may enable privesc paths): $line"
                    ;;
                *cap_fowner*)
                    print_finding "Interesting capability: cap_fowner (owner permission bypass may enable privesc paths): $line"
                    ;;
                *cap_net_admin*)
                    print_finding "Interesting capability: cap_net_admin (network admin surface; review context): $line"
                    ;;
                *cap_sys_ptrace*)
                    print_finding "Interesting capability: cap_sys_ptrace (process inspection/injection surface): $line"
                    ;;
            esac
        done
        echo
    else
        if [ "$rc_cap" -eq 124 ]; then
            echo "getcap: timed out."
        else
            echo "No file capabilities found or insufficient permissions."
        fi
        echo
    fi
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
        suid_out=$("$timeout_bin" "$timeout_arg" find / \( -type f -o -type d \) -perm -04000 -ls 2>/dev/null)
        rc_suid=$?
    else
        suid_out=$(find / \( -type f -o -type d \) -perm -04000 -ls 2>/dev/null)
        rc_suid=$?
    fi
    set +e

    if [ -n "$suid_out" ]; then
        printf '%s\n' "$suid_out"
        echo

        printf '%s\n' "$suid_out" | while IFS= read -r line; do
            case "$line" in
                */bash|*/sh|*/dash|*/zsh|*/ksh|*/find|*/vim|*/vi|*/nano|*/less|*/more|*/awk|*/mawk|*/gawk|*/sed|*/tar|*/zip|*/python|*/python2|*/python3|*/perl|*/ruby|*/php|*/node|*/nmap|*/openssl|*/env|*/cp|*/mv|*/rsync|*/scp|*/ssh|*/screen|*/tmux|*/docker|*/kubectl)
                    print_finding "Interesting SUID GTFOBins-style candidate: $line"
                    ;;
            esac
        done
    else
        echo "No SUID files/dirs found or insufficient permissions."
    fi

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
        sgid_out=$("$timeout_bin" "$timeout_arg" find / \( -type f -o -type d \) -perm -02000 -ls 2>/dev/null)
        rc_sgid=$?
    else
        sgid_out=$(find / \( -type f -o -type d \) -perm -02000 -ls 2>/dev/null)
        rc_sgid=$?
    fi
    set +e

    if [ -n "$sgid_out" ]; then
        printf '%s\n' "$sgid_out"
        echo

        printf '%s\n' "$sgid_out" | while IFS= read -r line; do
            case "$line" in
                */bash|*/sh|*/dash|*/zsh|*/ksh|*/find|*/vim|*/vi|*/nano|*/less|*/more|*/awk|*/mawk|*/gawk|*/sed|*/tar|*/zip|*/python|*/python2|*/python3|*/perl|*/ruby|*/php|*/node|*/nmap|*/openssl|*/env|*/cp|*/mv|*/rsync|*/scp|*/ssh|*/screen|*/tmux|*/docker|*/kubectl)
                    print_finding "Interesting SGID GTFOBins-style candidate: $line"
                    ;;
            esac
        done
    else
        echo "No SGID files/dirs found or insufficient permissions."
    fi

    if [ "$rc_sgid" -eq 124 ]; then
        echo "SGID find: timed out (timeout reached)."
    fi
    echo
}

container_docker_info() {
    print_subsection "Container context markers"

    if [ -f /.dockerenv ]; then
        print_finding "/.dockerenv exists: likely running inside Docker"
    else
        echo "/.dockerenv: not present"
    fi

    if [ -f /run/.containerenv ]; then
        print_finding "/run/.containerenv exists: likely running inside Podman/container environment"
    else
        echo "/run/.containerenv: not present"
    fi

    if [ -r /proc/1/cgroup ]; then
        cgroup_markers="$(grep -E 'docker|containerd|kubepods|podman|lxc' /proc/1/cgroup 2>/dev/null || true)"
        if [ -n "$cgroup_markers" ]; then
            print_finding "Container marker found in /proc/1/cgroup:"
            printf '%s\n' "$cgroup_markers"
        else
            echo "No obvious container marker found in /proc/1/cgroup."
        fi
    else
        echo "/proc/1/cgroup not readable."
    fi
    echo

    if [ -r /proc/mounts ]; then
        docker_mounts="$(grep -E 'docker.sock|/var/lib/docker|/run/docker|/run/containerd|/host|/mnt/host|/proc/sys|/sys/fs/cgroup' /proc/mounts 2>/dev/null || true)"
        if [ -n "$docker_mounts" ]; then
            print_finding "Interesting container/host-looking mounts:"
            printf '%s\n' "$docker_mounts"
        else
            echo "No obvious Docker/container host mounts found in /proc/mounts."
        fi
    else
        echo "/proc/mounts not readable."
    fi
    echo

    print_subsection "Docker access checks"

    groups_out="$(id -nG 2>/dev/null || true)"
    echo "Groups: ${groups_out:-unknown}"
    case " $groups_out " in
        *" docker "*)
            print_finding "Current user is in the docker group (often root-equivalent)"
            ;;
    esac

    for sock in /var/run/docker.sock /run/docker.sock; do
        if [ -e "$sock" ]; then
            ls -la "$sock" 2>&1
            if [ -S "$sock" ] && [ -w "$sock" ]; then
                print_finding "Docker socket appears writable by current user: $sock"
            elif [ -S "$sock" ] && [ -r "$sock" ]; then
                print_finding "Docker socket appears readable by current user: $sock"
            fi
        else
            echo "$sock: not present"
        fi
    done
    echo

    if command -v docker >/dev/null 2>&1; then
        print_finding "docker CLI available: $(command -v docker)"
    else
        echo "docker CLI not available."
        echo
        return 0
    fi

    if command -v docker-compose >/dev/null 2>&1; then
        echo "docker-compose CLI available: $(command -v docker-compose)"
    fi

    if docker compose version >/dev/null 2>&1; then
        echo "docker compose plugin available."
    fi
    echo

    print_subsection "Docker daemon"

    set +e
    docker info >/dev/null 2>&1
    docker_info_rc=$?
    set +e

    if [ "$docker_info_rc" -ne 0 ]; then
        echo "Docker daemon not reachable by current user or not running."
        run_cmd docker version
        return 0
    fi

    print_finding "Docker daemon reachable by current user"
    run_cmd docker version
    run_cmd docker info
    print_sub_subsection "docker ps -a"
    run_cmd docker ps -a
    print_sub_subsection "docker images"
    run_cmd docker images
    print_sub_subsection "docker volume ls"
    run_cmd docker volume ls
    print_sub_subsection "docker network ls"
    run_cmd docker network ls

    print_subsection "Suspicious Docker container settings"

    set +e
    container_ids="$(docker ps -aq 2>/dev/null || true)"
    set +e

    if [ -z "$container_ids" ]; then
        echo "No containers visible via docker ps -aq."
        echo
        return 0
    fi

    printf '%s\n' "$container_ids" | while IFS= read -r cid; do
        [ -z "$cid" ] && continue

        inspect_line="$(docker inspect --format 'Name={{.Name}} Privileged={{.HostConfig.Privileged}} PidMode={{.HostConfig.PidMode}} NetworkMode={{.HostConfig.NetworkMode}} Mounts={{range .Mounts}}{{.Source}}:{{.Destination}}:{{.Mode}};{{end}}' "$cid" 2>/dev/null || true)"
        [ -z "$inspect_line" ] && continue

        printf '%s\n' "$inspect_line"

        case "$inspect_line" in
            *"Privileged=true"*)
                print_finding "Docker container is privileged: $inspect_line"
                ;;
        esac

        case "$inspect_line" in
            *"PidMode=host"*)
                print_finding "Docker container uses host PID namespace: $inspect_line"
                ;;
        esac

        case "$inspect_line" in
            *"NetworkMode=host"*)
                print_finding "Docker container uses host network namespace: $inspect_line"
                ;;
        esac

        case "$inspect_line" in
            *"/var/run/docker.sock"*|*"/run/docker.sock"*)
                print_finding "Docker socket mounted into container: $inspect_line"
                ;;
        esac

        case "$inspect_line" in
            *":/:rw"*|*":/host:rw"*|*":/mnt/host:rw"*|*":/etc:rw"*|*":/root:rw"*|*":/home:rw"*|*":/var/run:rw"*)
                print_finding "High-risk writable host mount detected: $inspect_line"
                ;;
        esac
        echo
    done

    return 0
}

kubernetes_info() {
    print_subsection "Kubernetes environment markers"

    k8s_markers=0

    if [ -n "${KUBERNETES_SERVICE_HOST:-}" ]; then
        print_finding "KUBERNETES_SERVICE_HOST is set: $KUBERNETES_SERVICE_HOST"
        k8s_markers=1
    else
        echo "KUBERNETES_SERVICE_HOST: not set"
    fi

    if [ -n "${KUBERNETES_SERVICE_PORT:-}" ]; then
        print_finding "KUBERNETES_SERVICE_PORT is set: $KUBERNETES_SERVICE_PORT"
        k8s_markers=1
    else
        echo "KUBERNETES_SERVICE_PORT: not set"
    fi

    if [ -r /proc/1/cgroup ]; then
        k8s_cgroup="$(grep -E 'kubepods|kubelet|crio|containerd' /proc/1/cgroup 2>/dev/null || true)"
        if [ -n "$k8s_cgroup" ]; then
            print_finding "Kubernetes/container runtime marker found in /proc/1/cgroup:"
            printf '%s\n' "$k8s_cgroup"
            k8s_markers=1
        else
            echo "No Kubernetes marker found in /proc/1/cgroup."
        fi
    else
        echo "/proc/1/cgroup not readable."
    fi
    echo

    print_subsection "Kubernetes service account"

    sa_dir="/var/run/secrets/kubernetes.io/serviceaccount"
    if [ -d "$sa_dir" ]; then
        print_finding "Kubernetes service account directory exists: $sa_dir"
        ls -la "$sa_dir" 2>&1
        k8s_markers=1

        if [ -r "$sa_dir/token" ]; then
            print_finding "Kubernetes service account token is readable: $sa_dir/token"
        else
            echo "Service account token: missing or unreadable"
        fi

        if [ -r "$sa_dir/namespace" ]; then
            namespace="$(cat "$sa_dir/namespace" 2>/dev/null || true)"
            echo "Service account namespace: ${namespace:-unknown}"
        else
            echo "Service account namespace file: missing or unreadable"
        fi

        if [ -r "$sa_dir/ca.crt" ]; then
            echo "Service account CA certificate is readable: $sa_dir/ca.crt"
        else
            echo "Service account CA certificate: missing or unreadable"
        fi
    else
        echo "No Kubernetes service account directory found at $sa_dir."
    fi
    echo

    print_subsection "Kubernetes kubeconfig candidates"

    kube_found=0
    home_dir=${HOME:-}
    kube_paths="
$home_dir/.kube/config
/root/.kube/config
/etc/kubernetes/admin.conf
/etc/kubernetes/kubelet.conf
/etc/rancher/k3s/k3s.yaml
"
    for kube_path in $kube_paths; do
        [ -n "$kube_path" ] || continue
        if [ -e "$kube_path" ]; then
            kube_found=1
            ls -la "$kube_path" 2>&1
            if [ -r "$kube_path" ]; then
                print_finding "Readable kubeconfig candidate: $kube_path"
            else
                print_finding "Kubeconfig candidate exists but is not readable: $kube_path"
            fi
        fi
    done

    if [ "$kube_found" -eq 0 ]; then
        echo "No common kubeconfig candidates found."
    else
        k8s_markers=1
    fi
    echo

    print_subsection "kubectl access"

    if command -v kubectl >/dev/null 2>&1; then
        print_finding "kubectl CLI available: $(command -v kubectl)"
    else
        echo "kubectl CLI not available."
        echo
        if [ "$k8s_markers" -eq 0 ]; then
            echo "No Kubernetes markers found."
            echo
        fi
        return 0
    fi

    run_cmd kubectl version --client
    run_cmd kubectl config current-context
    run_cmd kubectl config get-contexts

    set +e
    kubectl auth can-i --list >/dev/null 2>&1
    can_i_rc=$?
    set +e

    if [ "$can_i_rc" -eq 0 ]; then
        print_finding "kubectl auth can-i --list succeeded"
        run_cmd kubectl auth can-i --list
    else
        echo "kubectl auth can-i --list failed or cluster is unreachable."
        run_cmd kubectl auth can-i --list
    fi

    set +e
    namespaces="$(kubectl get namespaces --no-headers 2>/dev/null | awk '{print $1}' || true)"
    set +e
    if [ -n "$namespaces" ]; then
        print_finding "kubectl can list namespaces"
        printf '%s\n' "$namespaces"
    else
        echo "kubectl cannot list namespaces or cluster is unreachable."
    fi
    echo

    run_cmd kubectl get pods -A

    set +e
    secrets_out="$(kubectl get secrets -A --no-headers 2>/dev/null || true)"
    set +e
    if [ -n "$secrets_out" ]; then
        print_finding "kubectl can list Kubernetes Secret objects (values not dumped):"
        printf '%s\n' "$secrets_out"
    else
        echo "kubectl cannot list Kubernetes Secret objects or none are visible."
    fi
    echo

    return 0
}

backup_leak_candidates() {
    if command -v timeout >/dev/null 2>&1; then
        timeout_bin="timeout"
        timeout_arg="60s"
    else
        timeout_bin=""
        timeout_arg=""
    fi

    roots="/etc /var/backups /home /root /opt /srv /var/www"
    found=0

    echo "Searching targeted backup/leak candidates in: $roots"
    echo "Heuristic only: backup-looking sensitive names, explicit .env/app config files, and SSH private key candidates."
    echo

    for root in $roots; do
        [ -e "$root" ] || continue

        print_sub_subsection "$root"

        set +e
        if [ -n "$timeout_bin" ]; then
            # shellcheck disable=SC2016
            leak_out=$("$timeout_bin" "$timeout_arg" find "$root" \
                \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o \
                \( -type f -o -type l \) -size -10240 \
                -exec sh -c '
                    for p do
                        case "$p" in
                            */id_rsa*|*/id_dsa*|*/id_ecdsa*|*/id_ed25519*) ls -ld "$p" ;;
                            */.ssh/*)
                                case "$p" in
                                    *.bak|*.backup|*.old|*.orig|*.save|*.swp|*.tmp|*.tar|*.tar.gz|*.tgz|*.zip|*.7z|*.gz) ls -ld "$p" ;;
                                esac
                                ;;
                            *.bak|*.backup|*.old|*.orig|*.save|*.swp|*.tmp|*.tar|*.tar.gz|*.tgz|*.zip|*.7z|*.gz)
                                case "$p" in
                                    *passwd*|*shadow*|*sudoers*|*crontab*|*cron.d*|*systemd*|*ssh*|*key*|*secret*|*token*|*credential*|*creds*|*password*|*.env*|*settings*|*database*|*wp-config*) ls -ld "$p" ;;
                                esac
                                ;;
                            */.env|*/.env.*|*/config.php|*/settings.py|*/database.yml|*/database.yaml|*/database.php|*/wp-config.php) ls -ld "$p" ;;
                        esac
                    done
                ' sh {} + 2>/dev/null)
            rc_leak=$?
        else
            # shellcheck disable=SC2016
            leak_out=$(find "$root" \
                \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o \
                \( -type f -o -type l \) -size -10240 \
                -exec sh -c '
                    for p do
                        case "$p" in
                            */id_rsa*|*/id_dsa*|*/id_ecdsa*|*/id_ed25519*) ls -ld "$p" ;;
                            */.ssh/*)
                                case "$p" in
                                    *.bak|*.backup|*.old|*.orig|*.save|*.swp|*.tmp|*.tar|*.tar.gz|*.tgz|*.zip|*.7z|*.gz) ls -ld "$p" ;;
                                esac
                                ;;
                            *.bak|*.backup|*.old|*.orig|*.save|*.swp|*.tmp|*.tar|*.tar.gz|*.tgz|*.zip|*.7z|*.gz)
                                case "$p" in
                                    *passwd*|*shadow*|*sudoers*|*crontab*|*cron.d*|*systemd*|*ssh*|*key*|*secret*|*token*|*credential*|*creds*|*password*|*.env*|*settings*|*database*|*wp-config*) ls -ld "$p" ;;
                                esac
                                ;;
                            */.env|*/.env.*|*/config.php|*/settings.py|*/database.yml|*/database.yaml|*/database.php|*/wp-config.php) ls -ld "$p" ;;
                        esac
                    done
                ' sh {} + 2>/dev/null)
            rc_leak=$?
        fi
        set +e

        if [ -n "$leak_out" ]; then
            found=1
            printf '%s\n' "$leak_out"
            echo

            printf '%s\n' "$leak_out" | while IFS= read -r line; do
                case "$line" in
                    */.ssh/*|*id_rsa*|*id_dsa*|*id_ecdsa*|*id_ed25519*)
                        print_finding "Potential credential leak: SSH private/key material candidate: $line"
                        ;;
                    *"/etc/sudoers.d/"*|*"/etc/shadow"*|*"/etc/passwd"*|*"/etc/sudoers"*)
                        print_finding "Potential privesc leak: account/sudo policy backup candidate: $line"
                        ;;
                    *".env"*|*"password"*|*"passwd"*|*"secret"*|*"token"*|*"credential"*|*"creds"*)
                        print_finding "Potential credential leak: secret-looking backup/config candidate: $line"
                        ;;
                    *"wp-config"*|*"database"*|*"settings"*|*"config"*)
                        print_finding "Potential app credential leak: config/database candidate: $line"
                        ;;
                    *"crontab"*|*"/cron.d/"*|*"systemd/system/"*|*.service)
                        print_finding "Potential privesc leak: scheduled task/service backup candidate: $line"
                        ;;
                esac
            done
            echo
        else
            if [ "$rc_leak" -eq 124 ]; then
                echo "Find: timed out while checking $root."
            else
                echo "No targeted backup/leak candidates found or insufficient permissions."
            fi
            echo
        fi
    done

    if [ "$found" -eq 0 ]; then
        echo "No targeted backup/leak candidates found in checked roots."
        echo
    fi

    return 0
}

credential_hunting() {
    if command -v timeout >/dev/null 2>&1; then
        timeout_bin="timeout"
        timeout_arg="60s"
    else
        timeout_bin=""
        timeout_arg=""
    fi

    roots="/home /root /var/www /opt /srv /etc"
    found=0

    echo "Searching targeted credential candidates in: $roots"
    echo "No secret values are printed here; keyword hits show file path and matched keyword names only."
    echo

    for root in $roots; do
        [ -e "$root" ] || continue

        print_sub_subsection "$root"

        set +e
        if [ -n "$timeout_bin" ]; then
            # shellcheck disable=SC2016
            cred_files=$("$timeout_bin" "$timeout_arg" find "$root" \
                \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path '*/.git' -o -path '*/node_modules' -o -path '*/vendor' -o -path '*/.cache' -o -path '*/__pycache__' \) -prune -o \
                \( -type f -o -type l \) -size -2048 \
                -exec sh -c '
                    for p do
                        case "$p" in
                            */.aws/credentials|*/.docker/config.json|*/.kube/config|*/.netrc|*/.git-credentials|*/.npmrc|*/.pypirc|*/.pgpass|*/.my.cnf|*/.ssh/config) ls -ld "$p" ;;
                            */credentials|*/credentials.json|*/secrets.yml|*/secrets.yaml|*/secrets.json|*/secret.yml|*/secret.yaml|*/secret.json) ls -ld "$p" ;;
                            */.env|*/.env.*|*/config.php|*/settings.py|*/database.yml|*/database.yaml|*/database.php|*/wp-config.php|*/application.properties|*/application.yml|*/application.yaml|*/docker-compose.yml|*/docker-compose.yaml) ls -ld "$p" ;;
                        esac
                    done
                ' sh {} + 2>/dev/null)
            rc_cred_files=$?
        else
            # shellcheck disable=SC2016
            cred_files=$(find "$root" \
                \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path '*/.git' -o -path '*/node_modules' -o -path '*/vendor' -o -path '*/.cache' -o -path '*/__pycache__' \) -prune -o \
                \( -type f -o -type l \) -size -2048 \
                -exec sh -c '
                    for p do
                        case "$p" in
                            */.aws/credentials|*/.docker/config.json|*/.kube/config|*/.netrc|*/.git-credentials|*/.npmrc|*/.pypirc|*/.pgpass|*/.my.cnf|*/.ssh/config) ls -ld "$p" ;;
                            */credentials|*/credentials.json|*/secrets.yml|*/secrets.yaml|*/secrets.json|*/secret.yml|*/secret.yaml|*/secret.json) ls -ld "$p" ;;
                            */.env|*/.env.*|*/config.php|*/settings.py|*/database.yml|*/database.yaml|*/database.php|*/wp-config.php|*/application.properties|*/application.yml|*/application.yaml|*/docker-compose.yml|*/docker-compose.yaml) ls -ld "$p" ;;
                        esac
                    done
                ' sh {} + 2>/dev/null)
            rc_cred_files=$?
        fi
        set +e

        if [ -n "$cred_files" ]; then
            found=1
            printf '%s\n' "$cred_files"
            echo

            printf '%s\n' "$cred_files" | while IFS= read -r line; do
                case "$line" in
                    *"/.aws/credentials"*|*"/.docker/config.json"*|*"/.kube/config"*|*"/.netrc"*|*"/.git-credentials"*|*"/.npmrc"*|*"/.pypirc"*|*"/.pgpass"*|*"/.my.cnf"*)
                        print_finding "Potential credential file: $line"
                        ;;
                    *"/.env"*|*"wp-config.php"*|*"database."*|*"settings.py"*|*"application."*|*"docker-compose."*)
                        print_finding "Potential app credential config: $line"
                        ;;
                    *"secret"*|*"credential"*)
                        print_finding "Potential secret/credential file: $line"
                        ;;
                esac
            done
            echo
        else
            if [ "$rc_cred_files" -eq 124 ]; then
                echo "Find: timed out while checking known credential file names in $root."
            else
                echo "No known credential file names found or insufficient permissions."
            fi
            echo
        fi

        set +e
        if [ -n "$timeout_bin" ]; then
            # shellcheck disable=SC2016
            keyword_hits=$("$timeout_bin" "$timeout_arg" find "$root" \
                \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path '*/.git' -o -path '*/node_modules' -o -path '*/vendor' -o -path '*/.cache' -o -path '*/__pycache__' \) -prune -o \
                -type f -size -2048 \
                -exec sh -c '
                    for p do
                        case "$p" in
                            *.env|*.conf|*.config|*.ini|*.yml|*.yaml|*.json|*.php|*.py|*.js|*.ts|*.properties|*.xml|*.txt|*.cnf|*.cfg|*.toml|*/.env|*/.env.*|*/.npmrc|*/.pypirc|*/.netrc|*/.pgpass|*/.my.cnf) ;;
                            *) continue ;;
                        esac
                        hits=$(grep -I -Ev "^[[:space:]]*#" "$p" 2>/dev/null | grep -Eio "db_password|mysql_password|postgres_password|redis_password|aws_secret_access_key|client_secret|private_key|access_key|api[_-]?key|apikey|password|passwd|pwd|secret|token" | sort -u | tr "\n" "|" | sed "s/|\$//")
                        [ -n "$hits" ] && printf "%s -> %s\n" "$p" "$hits"
                    done
                ' sh {} + 2>/dev/null)
            rc_keyword=$?
        else
            # shellcheck disable=SC2016
            keyword_hits=$(find "$root" \
                \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path '*/.git' -o -path '*/node_modules' -o -path '*/vendor' -o -path '*/.cache' -o -path '*/__pycache__' \) -prune -o \
                -type f -size -2048 \
                -exec sh -c '
                    for p do
                        case "$p" in
                            *.env|*.conf|*.config|*.ini|*.yml|*.yaml|*.json|*.php|*.py|*.js|*.ts|*.properties|*.xml|*.txt|*.cnf|*.cfg|*.toml|*/.env|*/.env.*|*/.npmrc|*/.pypirc|*/.netrc|*/.pgpass|*/.my.cnf) ;;
                            *) continue ;;
                        esac
                        hits=$(grep -I -Ev "^[[:space:]]*#" "$p" 2>/dev/null | grep -Eio "db_password|mysql_password|postgres_password|redis_password|aws_secret_access_key|client_secret|private_key|access_key|api[_-]?key|apikey|password|passwd|pwd|secret|token" | sort -u | tr "\n" "|" | sed "s/|\$//")
                        [ -n "$hits" ] && printf "%s -> %s\n" "$p" "$hits"
                    done
                ' sh {} + 2>/dev/null)
            rc_keyword=$?
        fi
        set +e

        if [ -n "$keyword_hits" ]; then
            found=1
            printf '%s\n' "$keyword_hits" | while IFS= read -r line; do
                print_finding "Potential credential keyword hit: $line"
            done
            echo
        else
            if [ "$rc_keyword" -eq 124 ]; then
                echo "Grep: timed out while checking credential keywords in $root."
            else
                echo "No credential keyword hits in targeted small text-like files."
            fi
            echo
        fi
    done

    if [ "$found" -eq 0 ]; then
        echo "No targeted credential candidates found in checked roots."
        echo
    fi

    echo "Credential inspection hint:"
    echo "  grep -I -En 'keyword1|keyword2' /path/to/file | grep -Ev '^[^:]+:[0-9]+:[[:space:]]*#'"
    echo "  Copy the path from the left side of '->' and the keyword list from the right side."
    echo

    return 0
}

home_content() {
    home_dir=${HOME:-}
    if [ -n "$home_dir" ] && [ -d "$home_dir" ]; then
        run_cmd ls -la "$home_dir"/
    else
        echo "HOME is not set or not accessible for this user."
        echo
    fi
}

print_section "BASIC SYSTEM CONTEXT"
print_subsection "id"
run_cmd id
print_subsection "uname -a"
run_cmd uname -a
print_subsection "env"
run_cmd env
ansi_reset
print_subsection "ls -la \$HOME"
home_content
print_section "PRIVILEGE & IDENTITY"
print_subsection "sudo -V"
run_sudo
print_section "EXECUTION ENVIRONMENT"
print_subsection "Available tools (categorized)"
check_tools
print_subsection "PATH hijack checks"
path_hijack_info
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
print_section "CONTAINERS & DOCKER"
container_docker_info
print_section "KUBERNETES"
kubernetes_info
print_section "BACKUPS & LEAKS"
print_subsection "Targeted sensitive backup/config candidates"
backup_leak_candidates
print_section "CREDENTIAL HUNTING"
print_subsection "Known credential files and keyword hits"
credential_hunting
print_section "USERS ENUMERATION"
enumerate_home_users
print_section "SCHEDULED TASKS & SERVICES"
print_subsection "cat /etc/crontab"
crontab_info
print_subsection "systemctl (print only suspicious)"
systemd_services_info
scheduled_task_writable_targets
print_section "PERMISSION SURFACES"
print_subsection "Find for files owned by root and group = each group of the invoking user"
files_owned_root
print_subsection "Find writable files/dirs owned by other users"
files_writable_other_users
print_subsection "File capabilities (getcap)"
list_file_capabilities
print_subsection "find files/dirs with SUID bit set (perm 04000)"
list_suid
print_subsection "find files/dirs with SGID bit set (perm 02000)"
list_sgid
