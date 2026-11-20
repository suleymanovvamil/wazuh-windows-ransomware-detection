# Known issues and fixes

Two rules triggered Active Response during testing without stopping anything useful. Both problems come from rule design, not from the AR script.

## 111007: NOT KILLED (allowed path)

**What happens:** 111007 fires, and the manager runs `kill-ransom.exe` on the agent. The alert's `image` is `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`. That path is under the allowlisted `C:\Windows\`, so the script logs `NOT KILLED (allowed path) ... review manually` (rule 110021).

**Root cause:** 111007 has no **current-event** file-write condition. It only has `if_matched_sid 110007` + `timeframe` + `same_location`. As a result it fires on the *second* `Set-MpPreference` process-creation event (Sysmon Event 1), and the alert carries PowerShell's PID instead of the encrypting process's.

Leaving PowerShell alone is the correct behavior for the script. The problem is which event the rule fires on.

**Fix:** make the current event a suspicious-extension file write, the same way 111008 is built:

```xml
<rule id="111007" level="15" frequency="2" timeframe="300">
  <if_sid>110002</if_sid>
  <if_matched_sid>110007</if_matched_sid>
  <same_location/>
  <description>Potential Ransomware Behaviour: $(win.eventdata.image) created files with suspicious extensions after Windows Defender was disabled</description>
  <mitre>
    <id>T1562.001</id>
    <id>T1486</id>
  </mitre>
</rule>
```

The alert then fires on the writer process's `.crypt` write, so AR gets the right PID and image.

## 111011: LOG ONLY and false-positive loop

**What happens:** `active-responses.log` gets about one `rule 111011: LOG ONLY (not a kill rule)` entry per second. The image is usually `kill-ransom.exe` itself, sometimes `wazuh-agent.exe`. Dashboard alerts show `targetFilename = C:\Windows\Temp\_MEI...\VCRUNTIME140.dll`.

**Root cause 1 (feedback loop):** `kill-ransom.exe` was built with PyInstaller `--onefile`. Each time it runs, it unpacks itself to `C:\Windows\Temp\_MEIxxxx` and deletes dozens of files on exit. Sysmon logs these as Event 23/26. Base rule 110011 has no path filter, so the deletes cross the 10/60 s threshold:

```
111011 fires → AR runs kill-ransom.exe → it deletes its _MEI files → 111011 fires again → ...
```

**Root cause 2 (nothing is killed):** 111011 is not in the script's `KILL_RULES` list, so the script only logs. Even if it were, the images (`kill-ransom.exe`, `wazuh-agent.exe`) are under the `C:\Program Files (x86)\` allowlist.

**Fixes (apply all):**
1. Add a path filter to 110011 so it only matches deletes inside monitored data folders, such as user profile documents or file shares.
2. Exclude the AR binary and `wazuh-agent.exe` from 110011:
   ```xml
   <field name="win.eventdata.image" type="pcre2" negate="yes">(?i)\\(kill-ransom|wazuh-agent)\.exe$</field>
   ```
3. Rebuild 111011 so that the current event is a suspicious-extension write (`if_sid 110002`) correlated with prior deletes. That is the "delete original + write encrypted copy" pattern.
4. Build the AR script with PyInstaller `--onedir`. The binary then no longer unpacks itself to Temp on every run.

## Smaller differences

- 111010's original description said "5+ ransom notes", but the rule uses `frequency="3"`. The description in this repo was corrected to match the rule.
- 111004 fires on **any** write to a canary file and has no "≥10 previous writes" condition. This is intentional (canaries shouldn't be touched at all), but it can be noisy if canaries sit in folders that backup or indexing software scans.
