# Active Response design (`kill-ransom`)

`kill-ransom` is a Windows Active Response script. It is written in Python and built into a single EXE with PyInstaller. When a kill-eligible rule fires, the Wazuh manager tells the agent that raised the alert (`location = local`) to run it. The script reads the alert from stdin, takes `win.eventdata.processId` and `win.eventdata.image`, and decides whether to kill.

## Safety checks

Killing the wrong process on an endpoint can do more damage than the alert it responds to, so the script is deliberately conservative:

| Check | Purpose |
|---|---|
| `KILL_RULES` | Only explicitly approved rule IDs can lead to a kill. Every other rule is `LOG ONLY`. |
| `PROTECTED_NAMES` | Never kill critical or security processes: `wazuh-agent.exe`, `sysmon.exe`, `MsMpEng.exe`, `lsass.exe`, `csrss.exe`, `services.exe`, `svchost.exe`, `winlogon.exe`, ... |
| `ALLOWED_PATHS` | Images under `C:\Windows\`, `C:\Program Files\` and `C:\Program Files (x86)\` are not killed. They are logged as `NOT KILLED (allowed path)` for manual review. |
| `ALLOWED_IMAGES` / `ALLOWED_HASHES` | Explicit allowlist for known-good tools (backup agents, sync clients, ...). |
| `SKIP_SIGNED` | Optionally skip processes with a valid Authenticode signature. |

**Recommended addition:** before killing, check that the PID's current image is still the image in the alert. This protects against PID reuse between the event and the response.

## Log format

Every decision is written as one line to `active-responses.log`. The manager rules in `rules/ransomware_rules.xml` match on these lines:

```
kill-ransom.exe: rule 111012: killed C:\Ransomware Lab\update.exe PID 1444                 → 110020 (level 13)
kill-ransom.exe: rule 111007: NOT KILLED (allowed path) C:\Windows\...\powershell.exe ...   → 110021 (level 10)
kill-ransom.exe: rule <id>: could not kill <image> PID <pid> ...                           → 110022 (level 12)
kill-ransom.exe: rule 111011: LOG ONLY (not a kill rule) ...                               → (no alert)
```

## Which rules kill and why

| Rule | Kill? | Reason |
|---|---|---|
| 111003 mass writes + ransom note | ✅ | Two independent strong signals from the same process |
| 111004 canary touch | ✅ | Canary files should never be modified |
| 111005 AppData encryptor | ✅ | User-writable location + mass encryption |
| 111007 Defender off + encryption | ✅ | Defense evasion + impact (needs the fix in known-issues.md) |
| 111008 shadow delete + encryption | ✅ | Recovery inhibition + impact |
| 111010 ransom note replication | ✅ | Repeated ransom notes |
| 111012 confirmed ransomware | ✅ | High-confidence encryption burst |
| 111001, 111002 | ❌ | One volume or extension anomaly is not enough |
| 111006 | ❌ | The current process is `vssadmin.exe` (native utility) |
| 111009 | ❌ | Context rule |
| 111011 | ❌ | Log only until the false-positive loop is fixed |

## Build note

Build with `pyinstaller --onedir`, not `--onefile`. A `--onefile` binary unpacks itself to `C:\Windows\Temp\_MEIxxxx` and deletes those files on every run, which is exactly what deletion-based ransomware rules look for (see 111011 in known-issues.md).
