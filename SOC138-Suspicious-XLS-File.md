# SOC138 - Detected Suspicious XLS File Analysis

> **Platform:** LetsDefend  
> **Alert ID:** 77  
> **Date Analyzed:** April 22, 2026  
> **Analyst:** Matanat

---

## 📋 Alert Summary

| Field | Value |
|-------|-------|
| **Rule Name** | SOC138 - Detected Suspicious Xls File |
| **Event Time** | Mar 13, 2021 - 08:20 PM |
| **Severity** | Medium |
| **Alert Type** | Malware |
| **MITRE Technique** | T1112 - Defense Evasion: Modify Registry |
| **Source Address** | 172.16.17.56 |
| **Source Hostname** | Sofia |
| **File Name** | ORDER SHEET & SPECIFICATIONS.xls |
| **File Hash (MD5)** | 7ccf88c0bbe3b29bf19d877c4596a8d4 |
| **File Size** | 2.66 MB |
| **Device Action** | ⚠️ Allowed |

---

## 🎯 Investigation Workflow

### Step 1: Initial Triage

A SIEM alert was triggered indicating that a suspicious Excel file had reached an endpoint (Sofia / 172.16.17.56). The file was **not blocked** (Device Action: Allowed) — a critical detail, as it means the user may have opened it.

**Initial hypothesis:** Phishing campaign delivering a malicious macro-enabled Excel document.

---

### Step 2: Static Analysis - Hash Reputation

I queried the file's MD5 hash on VirusTotal.

**Hash:** `7ccf88c0bbe3b29bf19d877c4596a8d4`

**VirusTotal Findings:**
- Multiple AV engines flagged the file as malicious
- Malware family: Macro-based downloader (Office document with malicious VBA)
- File previously known and reported as malicious

✅ **Conclusion:** The file was confirmed as malicious with high confidence.

---

### Step 3: Dynamic Analysis - Sandbox Execution

I detonated the sample in an isolated sandbox environment (Any.run) for behavioral analysis.

**Observed Behaviors:**

- **Macro Execution:** The VBA macro auto-executed when the Excel file was opened
- **Process Spawning:** Child processes were spawned under EXCEL.EXE (PowerShell / cmd.exe)
- **Registry Modification:** Modifications were made to registry keys (consistent with T1112 - Modify Registry)
- **Network Activity:** Outbound connection attempts to external IP addresses were detected (potential C2 communication)
- **File System Activity:** Additional files were dropped to temporary directories

---

### Step 4: MITRE ATT&CK Mapping

| Technique ID | Tactic | Description |
|-------------|--------|-------------|
| T1566.001 | Initial Access | Spearphishing Attachment |
| T1204.002 | Execution | User Execution: Malicious File |
| T1059.005 | Execution | Command and Scripting Interpreter: Visual Basic |
| T1112 | Defense Evasion | Modify Registry |

---

## 🔍 Indicators of Compromise (IOCs)

### File Indicators
| Type | Value |
|------|-------|
| MD5 | `7ccf88c0bbe3b29bf19d877c4596a8d4` |
| Filename | ORDER SHEET & SPECIFICATIONS.xls |
| File Size | 2.66 MB |

### Host Indicators
| Type | Value |
|------|-------|
| Affected Host | Sofia |
| Source IP | 172.16.17.56 |

---

## ⚖️ Verdict & Actions Taken

**Verdict:** ✅ **True Positive** — Confirmed malicious file

**Actions Taken:**
1. Recommended containment / isolation of endpoint Sofia (172.16.17.56)
2. File hash flagged for inclusion in EDR and security tool blocklists as IOC
3. Recommended credential reset for the affected user
4. Suggested detection rule on mail gateway to catch similar phishing campaigns
5. Case marked as **Closed**

---

## 💡 Lessons Learned

### Technical Takeaways
- The **Device Action: Allowed** flag was a critical indicator — since the system did not block the file, manual response was essential
- VBA macro-based attacks remain one of the most common initial access vectors
- Combining hash reputation lookup with sandbox analysis provides fast and reliable verdicts

### Process Improvements
- Endpoint policy "Macros from the internet" should be set to **block** by default
- An additional inspection layer for macro-enabled Office documents should be added at the mail gateway
- User awareness training should be reinforced to address the human factor in phishing attacks

---

## 🛠️ Tools Used

- **VirusTotal** — Hash reputation analysis
- **Any.run** — Sandbox dynamic analysis
- **LetsDefend Platform** — SIEM investigation
- **MITRE ATT&CK Navigator** — Technique mapping

---

## 📚 References

- [MITRE T1112 - Modify Registry](https://attack.mitre.org/techniques/T1112/)
- [MITRE T1566.001 - Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [VirusTotal](https://www.virustotal.com/)
- [Any.run Sandbox](https://app.any.run/)

---

**Analyst Note:** This case represents a typical phishing-delivered, macro-based malware infection chain. Rapid triage using hash reputation lookup combined with sandbox detonation enabled a confident verdict within a short timeframe — a representative SOC L1 workflow.
