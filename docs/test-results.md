# Test results

The rules were tested in an isolated lab: a Wazuh manager (Linux VM) and one Windows 10 agent running Sysmon. A **benign ransomware simulator** played the attacker. It was a PyInstaller-built EXE that only works inside a dedicated lab folder. It renames dummy files to `.crypt`, drops ransom notes, and runs the usual tampering commands.

## Lab setup

| Component | Details |
|---|---|
| Manager | Wazuh 4.x on a Linux VM, rules in `/var/ossec/etc/rules/local_rules.xml` |
| Endpoint | Windows 10 + Sysmon, Wazuh agent |
| Test data | `C:\Ransomware Lab\Files\` with 50 dummy files (docx, xlsx, pdf, txt), plus two subfolders |
| Simulator | `update.exe` (benign), run from the lab folder and from an `AppData\Roaming` path |
| Active Response | `kill-ransom.exe` (Python, built with PyInstaller `--onefile`) |

Telemetry check: Sysmon Event ID 11 (FileCreate) events with `Image = ...\update.exe` and `TargetFilename = ...\*.crypt` showed up in Event Viewer. On the manager they showed up in `archives.json` with decoded `win.eventdata.*` fields (`image`, `processGuid`, `processId`, `targetFilename`).

## Per-rule results

### 111001: Mass document write burst
- **Logic:** 20+ FileCreate events in 30 s from the same `image` + `processGuid`
- **Level / MITRE:** 10 / T1486. **AR:** no (one volume anomaly isn't enough)
- **Result:** ✅ Fired (7 hits). `previous_output` shows the sequence of Event 11 events from the same ProcessGuid.

### 111002: Suspicious encrypted-extension burst
- **Logic:** 10+ files with ransomware-like extensions in 30 s from the same `processGuid`
- **Extensions:** `.crypt .crypted .crypto .encrypt(ed) .enc .lock(ed) .locky .ryk .wncry .wnry .cerber .zepto .odin .ransom`
- **Level / MITRE:** 12 / T1486. **AR:** no
- **Result:** ✅ Fired (5 hits). All 50 lab files ended up as `.crypt`.

### 111003: Mass writes + ransom note
- **Logic:** a ransom-note filename (`read_me`, `how_to_decrypt`, `restore_files`, `decrypt_instructions`, `recovery_file`, ...) written by a process that already matched 110001 within 60 s
- **Level / MITRE:** 14 / T1486. **AR:** yes
- **Result:** ✅ Fired. 🛑 **AR killed the process** (`rule 111003: killed C:\Ransomware Lab\trigger_111003.exe`).

### 111004: Canary file touch
- **Logic:** any write to a file whose name contains `canary`
- **Level / MITRE:** 15 / T1486. **AR:** yes
- **Result:** ⚠️ The rule is deployed, but the alert and AR result were not captured during testing.

### 111005: AppData writer burst
- **Logic:** a process running from `\Users\*\AppData\` creates 15+ files with suspicious extensions in 120 s
- **Level / MITRE:** 14 / T1486. **AR:** yes
- **Result:** ✅ Fired (1 hit) with the simulator run from `AppData\Roaming\Microsoft\update.exe`. The AR result was not captured.

### 111006: Recovery inhibition sequence
- **Logic:** `vssadmin delete shadows` seen 2+ times in 300 s on the same agent
- **Level / MITRE:** 15 / T1490. **AR:** no, by design. The current process is `vssadmin.exe`, a native Windows utility.
- **Result:** ✅ Fired (2 hits).

### 111007: Defender disable + encryption
- **Logic:** `Set-MpPreference ... -Disable* $true` followed by activity on the same agent within 600 s
- **Level / MITRE:** 15 / T1562.001, T1486. **AR:** yes
- **Result:** ✅ Fired (1 hit). ⚠️ AR was called but **did not kill**: `NOT KILLED (allowed path) ...\powershell.exe`. See [known-issues.md](known-issues.md#111007--not-killed-allowed-path).

### 111008: Shadow copy deletion + encryption
- **Logic:** a suspicious-extension file write (current event) after `vssadmin delete shadows` by the same user
- **Level / MITRE:** 15 / T1490, T1486. **AR:** yes
- **Result:** ✅ Fired (51 hits). The final alert fires on the writer process (`update.exe`), so AR gets the correct PID and image.

### 111009: Security log clear + encryption
- **Logic:** an encryption-related alert after Windows Security log clear (Event 1102) within 600 s
- **Level / MITRE:** 15 / T1070.001, T1486. **AR:** no (conditional)
- **Result:** ✅ Fired (52 hits). Adding `ignore="300"` reduced repeat alerts.

### 111010: Ransom note replication
- **Logic:** 111003 fires 3+ times in 60 s for the same `processGuid`
- **Level / MITRE:** 15 / T1486. **AR:** yes
- **Result:** ✅ Fired (2 hits). 🛑 **AR killed the process** (`rule 111010: killed ...\AppData\Roaming\update.exe`).

### 111011: Mass deletion
- **Logic:** 10+ Sysmon Event 23/26 deletes in 60 s from the same `processGuid`
- **Level / MITRE:** 15 / T1485, T1486. **AR:** log only
- **Result:** ⚠️ Fired (29 hits), but they were **false positives** from the AR binary itself. See [known-issues.md](known-issues.md#111011--log-only-and-false-positive-loop).

### 111012: High-confidence local ransomware
- **Logic:** 10+ files with suspicious extensions in 60 s from the same `processGuid` (process not in AppData)
- **Level / MITRE:** 15 / T1486. **AR:** yes (mandatory)
- **Result:** ✅ Fired (10 hits). 🛑 **AR killed the simulator in two separate test runs.**

## Active Response summary

| Trigger rule | Process | Result |
|---|---|---|
| 111003 | `C:\Ransomware Lab\trigger_111003.exe` | ✅ killed |
| 111010 | `...\AppData\Roaming\update.exe` | ✅ killed |
| 111012 | `C:\Ransomware Lab\update.exe` (run 1) | ✅ killed |
| 111012 | `C:\Ransomware Lab\update.exe` (run 2) | ✅ killed |
| 111007 | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | ⚠️ NOT KILLED (allowed path) |
| 111011 | `kill-ransom.exe`, `wazuh-agent.exe` | ⚠️ LOG ONLY (not a kill rule) |

Every AR action is written to the agent's `active-responses.log`. The agent forwards it to the manager, where rules 110020, 110021 and 110022 turn it into Dashboard alerts. A `rule.id: 110020` query showed 17–20 "ransomware process killed" alerts.

## Gaps and not yet tested

- The 111004 alert and the AR results for 111005 and 111008 were not captured.
- No false-positive (negative) tests were run against benign bulk-file activity, such as backups, archive extraction or software updates.
- The `kill-ransom` script does not yet verify that the alert's PID still belongs to the same image before killing (protection against PID reuse).
