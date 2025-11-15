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

### BoberLenum — lightweight parameter‑aware Linux enumeration script

BoberLenum is a minimal Bash enumeration script inspired by linpeas.sh. It is not a replacement for linpeas or any comprehensive privilege‑escalation scanner — it runs a handful of basic checks and collects a shallow, quick snapshot of a target system to aid manual triage and follow‑up investigation.

---

### What it does (summary)

- Runs basic system queries: id, uname, env, sudo version, sudo -l (with special handling), and basic file listings (home, /var/www, /opt).
- Detects commonly available tools (wget, curl, python, php, etc.).
- Optionally downloads remote helpers (pspy, linpeas) from an HTTP server you specify and marks them executable.
- Enumerates users by scanning /home/* and reports per‑user details (passwd/getent, id, lastlog, ssh, history files, crontabs, basic mail spool email extraction).
- Finds files owned by root and files with SUID/SGID bits, using timeouts where available to avoid long hangs.
- Performs length and format validation on supplied parameters (password, IP, filenames) and verifies a provided sudo password before using it to run sudo‑requiring checks.

---

### Quick start and usage

- Make the script executable and run locally: chmod +x BoberLenum.sh ./BoberLenum.sh [options]
    
- Options:
    
    - **-pw` <password>`** : supply current user sudo password to attempt verification and non‑interactive sudo commands. The script detects and refuses to verify when sudo is configured NOPASSWD or the user is not in sudoers.
    - **-ip `<IPv4>`** : required when requesting remote downloads (-pspy or -linpeas). Must be a valid IPv4 address.
    - **-pspy `<filename>`** : download http://`<ip>`/`<filename>` and mark executable (if wget/curl present).
    - **-linpeas `<filename>`** : download http://`<ip>`/`<filename>` and mark executable (if wget/curl present).
    - **-h, --help** : show help and exit.
- Important parameter rules:
    
    - If any parameters are provided, they are validated.
    - If -ip is provided, at least one of -pspy or -linpeas must be provided.
    - Password verification uses sudo and will fail if sudo is passwordless or if the invoking user is not in sudoers.
- Examples:
    
    - Run a plain enumeration (no validations or downloads): `./BoberLenum.sh`
    - Verify sudo password and attempt a linpeas download from 10.0.0.5:
    ```
    ./BoberLenum.sh -pw 'MySudoPass' -ip 10.0.0.5 -linpeas linpeas.sh
    ```
---

### Behavior and implementation notes

- Validation and safety:
    - Password length is limited (default MAX_PW_LEN=256). Filenames are limited (MAX_NAME_LEN=30). IPs are validated for IPv4 format and octet ranges.
    - When verifying a password, the script invalidates any cached sudo timestamp and checks whether sudo is passwordless before attempting to verify.
- Non‑fatal by design:
    - Many operations are intentionally non‑fatal: failures are reported but do not stop the script (finds, downloads, crontab reads, etc.). Timeouts are used where possible to avoid long system scans.
- Output:
    - Uses ANSI styling (when attached to a TTY) to improve readability and prints labeled headers for commands it runs.
- Download behavior:
    - Prefers wget, falls back to curl. Applies a DOWNLOAD_TIMEOUT (default 7s) and cleans up partial files on failure.
- Safety about running commands:
    - The script avoids scanning /proc and skips running costly find operations on the invoking user's own files.

---

### Security, legal & responsible use

- Only run BoberLenum on systems you own, administer, or on which you have explicit authorization. Running enumeration or download operations against machines you do not control may be illegal and unethical.
- The script may attempt to validate sudo credentials and may send a provided password to sudo. Do not provide real credentials unless you trust the environment and understand the risks.
- The download feature fetches remote executables over plain HTTP; prefer running over isolated networks and avoid exposing sensitive data.

---
