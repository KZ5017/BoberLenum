<p align="center">
  <img width="768" height="514" alt="BoberLenum" src="https://github.com/user-attachments/assets/115ace16-599c-46ef-a5ac-a3b188370822" />
</p>

# BoberLenum 🦫

BoberLenum is a lightweight Linux enumeration script designed to quickly collect useful context during post-exploitation, CTFs, or controlled security assessments.

It focuses on **clarity, ordering, and signal-over-noise**, rather than exhaustive coverage.

> ⚠️ This is **not** a LinPEAS replacement and does **not** aim to be in the same weight class.

---

## What this is

- ✔ A **single-file POSIX shell** enumeration script
- ✔ Runs sequentially and prints readable, structured output
- ✔ Collects **common privilege escalation signals** and environment context
- ✔ Intended for **manual analysis**, not automated exploitation

---

## What this is *not*

- ❌ Not a vulnerability scanner  
- ❌ Not an exploit framework  
- ❌ Not a LinPEAS / LinEnum competitor  
- ❌ No kernel exploit matching or CVE detection  

Think of it as a **calm first look**, not a full audit.

---

## 🧠 Enumerated areas (high-level)

- Basic system context (id, uname, env)
- Available binaries grouped by category (networking, interpreters, containers, LOLBins, etc.)
- User and home directory enumeration
- SSH artifacts, history files, cron jobs
- Network configuration and listening services
- Filesystems, mounts, NFS exports
- systemd services with non-standard executables
- Permission surfaces:
  - SUID / SGID files
  - Root-owned files accessible by user groups

---

## ✨ Design goals

- **Readable output** over raw volume
- **Preserve execution order** for reproducibility
- **Fail-safe execution** (timeouts, error handling)
- Minimal assumptions about installed tooling

---

## 🚀 Usage

```bash
chmod +x boberlenum.sh
./boberlenum.sh
```

No arguments are required.

---

## Operational notes

- Some sections may produce large output depending on permissions
    
- `find` operations are time-limited when `timeout` is available
    
- `/proc` is intentionally excluded from filesystem scans
    
- Script is read-only and does not modify system state
    

---

## Intended use

- CTFs and labs (HTB, THM, VulnHub)
    
- Internal red team assessments
    
- Manual privilege escalation workflows
    
- Educational / learning purposes
    

---

## ⚠️ Disclaimer

This script is provided for **educational and authorized security testing only**.  
Do not run it on systems you do not own or have explicit permission to test.

---

## 📜 License

MIT
