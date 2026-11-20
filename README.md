# Wazuh Windows Ransomware Detection

Behavioral detection rules, correlation rules and an automated **Active Response** setup that detect and stop ransomware on Windows endpoints with **Wazuh + Sysmon**.

Classic signature detection misses new ransomware families. These rules focus on what ransomware *does*: mass file encryption, ransom notes, shadow copy deletion, Defender tampering, log clearing and canary file access. They correlate those signals per process (`processGuid`) and kill the offending process when the evidence is strong enough.

## Features

- **12 correlation rules** (111001–111012) built on Sysmon Event IDs 1, 11, 23 and 26 plus Windows Security Event 1102
- **MITRE ATT&CK mapping:** T1486, T1490, T1562.001, T1070.001, T1485
- **Per-process correlation** with `same_field: win.eventdata.processGuid`, so separate processes don't add up to a false alarm
- **Tiered response:** context rules only alert; high-confidence rules trigger Active Response
- **Safe kill logic:** protected-process list, path and hash allowlists, and a log-only default
- **AR visibility:** kill / not-killed / failed results come back to the Dashboard as alerts (110020–110022)
- **Tested** against a benign ransomware simulator. Results and known issues are documented.

## Detection rules

| Rule | Detection | Level | MITRE | Active Response |
|---|---|:-:|---|:-:|
| 111001 | 20+ file writes in 30 s by one process | 10 | T1486 | – |
| 111002 | 10+ files with ransomware extensions in 30 s | 12 | T1486 | – |
| 111003 | Mass writes followed by a ransom note | 14 | T1486 | ✅ |
| 111004 | Canary file modified | 15 | T1486 | ✅ |
| 111005 | Process from `AppData` encrypts 15+ files in 120 s | 14 | T1486 | ✅ |
| 111006 | `vssadmin delete shadows` 2+ times in 300 s | 15 | T1490 | – |
| 111007 | Defender disabled → encryption | 15 | T1562.001, T1486 | ✅ |
| 111008 | Shadow copies deleted → encryption | 15 | T1490, T1486 | ✅ |
| 111009 | Security log cleared → encryption | 15 | T1070.001, T1486 | – |
| 111010 | Multiple ransom notes in 60 s | 15 | T1486 | ✅ |
| 111011 | 10+ file deletions in 60 s | 15 | T1485, T1486 | log only |
| 111012 | **Confirmed:** 10+ encrypted files in 60 s | 15 | T1486 | ✅ |

Base and atomic rules use the 1100xx range, and AR result monitoring uses 110020–110022.

## Repository layout

```
├── rules/
│   └── ransomware_rules.xml        # all detection + AR-monitoring rules
├── active-response/
│   └── ossec.conf.snippet.xml      # manager command + active-response block
└── docs/
    ├── test-results.md             # lab setup and per-rule test results
    ├── active-response.md          # kill-ransom design and safety checks
    └── known-issues.md             # issues found in testing + fixes
```

## Quick start

### 1. Prerequisites
- Wazuh manager 4.x
- Windows agent with [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) logging **Event IDs 1, 11, 23 and 26**
- Agent `ossec.conf` collecting `Microsoft-Windows-Sysmon/Operational` and the `Security` event channel

### 2. Install the rules (manager)
```bash
sudo cp rules/ransomware_rules.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/ransomware_rules.xml
sudo /var/ossec/bin/wazuh-logtest    # optional: validate
sudo systemctl restart wazuh-manager
```

### 3. Configure Active Response (manager)
Add the contents of [`active-response/ossec.conf.snippet.xml`](active-response/ossec.conf.snippet.xml) inside `<ossec_config>` in `/var/ossec/etc/ossec.conf`, then restart the manager.

### 4. Deploy the AR binary (agent)
Put your `kill-ransom.exe` in:
```
C:\Program Files (x86)\ossec-agent\active-response\bin\
```
See [docs/active-response.md](docs/active-response.md) for the logic and safety checks the script needs.

To see AR results on the Dashboard, have the agent forward `active-responses.log`:
```xml
<localfile>
  <location>C:\Program Files (x86)\ossec-agent\active-response\active-responses.log</location>
  <log_format>syslog</log_format>
</localfile>
```

### 5. Plant canary files (optional, for 111004)
Put decoy files with `canary` in their names (for example `~canary_finance.docx`) in folders worth protecting.

## Test results

| Result | Rules |
|---|---|
| ✅ Fired + process killed | 111003, 111010, 111012 (twice) |
| ✅ Fired (alert-only by design) | 111001, 111002, 111006, 111009 |
| ✅ Fired (AR result not captured) | 111005, 111008 |
| ⚠️ Fired, AR did not kill | 111007 (PowerShell is allowlisted; rule fix provided) |
| ⚠️ False-positive loop | 111011 (AR binary self-trigger; fix provided) |
| ⏳ Not captured | 111004 |

Details: [docs/test-results.md](docs/test-results.md) · Fixes: [docs/known-issues.md](docs/known-issues.md)

## ⚠️ Before production

- Apply the fixes in [known-issues.md](docs/known-issues.md) for **111007** and **111011**.
- Tune the thresholds and the extension list for your environment. Backup tools, archivers, software updates and sync clients can create many files quickly.
- Add your legitimate bulk-writing tools to the AR allowlist.
- Run negative (benign) tests before turning on automatic kills.
- Tests used a benign simulator only. No real malware was involved.

## License

MIT. See [LICENSE](LICENSE).
