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

# BoberLenum 🦫

**BoberLenum** is a lightweight Linux enumeration script intended for quick situational awareness during CTFs, labs, and controlled security assessments.

> ⚠️ **Important note**  
> This is **not** a replacement for linPEAS.  
> BoberLenum intentionally stays lightweight and readable, and does **not** aim to compete with full-scale automated privilege escalation frameworks.

---

## ✨ Project Philosophy

BoberLenum was created with the following goals in mind:

- Fast, no-friction local enumeration
- Human-readable output
- Minimal dependencies
- Easy auditing and customization
- Suitable for constrained or monitored environments

If you need exhaustive checks, exploit suggestions, and heavy heuristics, **linPEAS is the better choice**.  
If you want a **clean, structured overview of the system without noise**, BoberLenum fits well.

---

## 🧠 What BoberLenum Does

BoberLenum enumerates:

- System and kernel context
- User and home directory information
- Sudo capabilities (with optional password verification)
- Installed tools (categorized)
- Network configuration
- Mounted filesystems and exports
- Cron jobs and systemd services
- Permission surfaces (SUID/SGID, group-accessible root files)
- Optional helper tool downloads (pspy, linpeas)

All checks are designed to be **non-exploitative** and **read-only**.

---

## 📦 Available Variants (4 + 1)

This project is intentionally released in multiple variants to fit different operational needs.

### 1️⃣ Base Version (Full Featured - BoberLenum.sh)

- Bash-based
- Parameter-aware
- Optional password verification
- Optional helper downloads (pspy / linpeas)
- Rich output with colors and sections

This is the reference implementation.

---

### 2️⃣ Base – No Parameters (BoberLenum_param-less.sh)

- Same enumeration logic
- No arguments required
- Runs immediately
- Ideal for quick copy & execute scenarios

---

### 3️⃣ POSIX `sh` Compatible Version (BoberLenum_param-less_sh.sh)

- Fully `/bin/sh` compatible
- No Bash-specific features
- Still parameterless
- Increased portability across minimal systems

---

### 4️⃣ Compact POSIX Version (BoberLenum_param-less_sh_mini.sh)

- `sh` compatible
- Highly compact
- Size-optimized
- Trades off a small amount of functionality:
  - Tool availability check removed
  - `lsblk` enumeration removed

This version is intended for:
- Very restricted environments
- Payload size constraints

---

### ➕ +1 Encoded Dropper Version (BoberLenum_from_b64.md)

- Based on the **compact POSIX version**
- Base64 encoded
- Chunked
- Fully copy-pasteable

Intended for:
- Manual terminal-only delivery
- Environments without file transfer options

---

## 🚀 Usage

Example (base version):

```bash
chmod +x BoberLenum.sh
./BoberLenum.sh
```

With optional parameters:

```bash
./BoberLenum.sh -pw MySudoPassword -ip 10.10.10.10 -pspy pspy64
```

> Parameters are strictly validated.  
> If parameters are provided, consistency rules apply.

---

## ⚠️ Disclaimer

This tool is intended **for educational purposes and authorized security testing only**.

Do **NOT** run this script on systems you do not own or have explicit permission to test.

The author takes no responsibility for misuse.

---

## 🛠️ Customization

BoberLenum is intentionally written in a readable and modular way.  
Feel free to:

- Remove sections
    
- Add custom checks
    
- Adjust timeouts
    
- Modify output verbosity
    

---

## 🤝 Inspiration

- linPEAS
    
- manual Linux privilege escalation checklists
    
- real-world CTF and lab workflows
    

---

## 📜 License

MIT License
