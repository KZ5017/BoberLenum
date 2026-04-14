<p align="center">
  <img width="768" height="514" alt="BoberLenum" src="https://github.com/user-attachments/assets/115ace16-599c-46ef-a5ac-a3b188370822" />
</p>

# BoberLenum

BoberLenum is a single-file Linux enumeration script for post-exploitation, CTFs, labs, and authorized security assessments.

It aims for a calm first pass: readable sections, practical privilege-escalation signals, and a better signal-to-noise ratio than a raw “dump everything” script.

> This is not a LinPEAS replacement. It is intentionally smaller, more manual, and easier to read.

---

## What This Is

- Single-file POSIX `sh` enumeration script
- Best-effort execution: missing tools, unreadable files, and failed probes should not stop the run
- Structured output with clear sections and highlighted findings
- Read-only by design: it collects and prints information, it does not exploit or modify the target
- Built for manual review, not automated vulnerability scoring

---

## What This Is Not

- Not a vulnerability scanner
- Not an exploit framework
- Not kernel/CVE matching
- Not a full system audit
- Not a replacement for deeper manual testing

Think of it as a focused map of interesting surfaces.

---

## Main Coverage

- Basic system context: `id`, `uname`, environment, `$HOME`
- Privilege and identity checks: `sudo -V`, non-interactive `sudo -n -l`
- Execution environment:
  - Available tools grouped by category
  - PATH hijack checks
  - Custom systemd unit listing with review hints
  - `/etc/profile.d` listing with review hints
- Networking:
  - Interfaces
  - `/etc/hosts`
  - `/etc/resolv.conf`
  - Listening sockets via `netstat` or `ss`
- Filesystem and storage:
  - `lsblk`
  - `findmnt`
  - NFS exports
  - Mount option hints for interesting writable/shared mounts
  - `/var/www` and `/opt` directory listing
- Containers and Docker:
  - Container markers
  - Docker socket checks
  - Docker group membership
  - Docker daemon access
  - Suspicious container settings such as privileged mode, host namespace use, Docker socket mounts, and writable host mounts
- Kubernetes:
  - Kubernetes environment markers
  - Service account token/namespace/CA presence
  - Kubeconfig candidates
  - Read-only `kubectl` access checks when available
- Backups and leaks:
  - Targeted backup-looking sensitive files
  - SSH key candidates
  - Sensitive config backup candidates
- Credential hunting:
  - Known credential file names
  - Small targeted text/config files
  - Keyword-only hits without printing secret values
  - Grep hint for manual follow-up
- Users:
  - Home directory users
  - User metadata
  - SSH directory/history file hints
  - User crontabs when available
- Scheduled tasks and services:
  - `/etc/crontab`
  - Suspicious systemd services using non-standard binaries
  - Writable cron/systemd target heuristics
- Permission surfaces:
  - Root-owned files accessible by current user groups
  - Writable files/directories owned by other users
  - File capabilities with risk-focused highlighting
  - SUID/SGID files with GTFOBins-style candidate highlighting

---

## Output Philosophy

BoberLenum prints both raw context and highlighted findings.

The raw context is there so you can verify the situation yourself. The red findings are intended as “look here first” markers, not proof of exploitability.

Some sections intentionally avoid dumping sensitive values. For example, credential hunting reports the path and matched keyword names, then gives a grep command hint so the operator can inspect the exact lines manually.

---

## Usage

```bash
chmod +x BoberLenum.sh
./BoberLenum.sh
```

No arguments are required.

---

## Operational Notes

- The script is best-effort and should continue even when a probe fails.
- `find` and similar broad checks use `timeout` when available.
- `/proc` is intentionally excluded from broad filesystem scans.
- Docker and Kubernetes checks are read-only, but their output depends heavily on local permissions.
- Credential hunting does not print secret values by design.
- Some environments will still produce noise. Treat findings as triage hints.

---

## Intended Use

- CTFs and lab machines
- Internal red team and authorized assessments
- Manual Linux privilege escalation workflows
- Learning and note-taking during enumeration

---

## Disclaimer

This script is provided for educational and authorized security testing only. Do not run it on systems you do not own or do not have explicit permission to test.

---

## License

MIT
