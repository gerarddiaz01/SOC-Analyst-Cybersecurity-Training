# Threat Simulation & Detection Engineering — Pyramid of Pain Investigation

* **Date:** 18-04-2026
* **Investigator:** Gerard Diaz Gibert
* **Environment:** TryHackMe — Summit — Virtual Lab (PicoSecure Purple Team Simulation)
* **Scenario:** Iterative adversary simulation across all seven levels of the Pyramid of Pain — from hash-based detection up to full TTP behavioral analysis

---

## 1. Alert Scenario & Initial Context

PicoSecure initiated a purple-team threat simulation engagement to evaluate and improve its malware detection capabilities. An external penetration tester (Sphinx) was tasked with executing a series of progressively sophisticated malware samples on a simulated internal workstation. My role was to analyze each sample, identify the relevant indicator of compromise, and deploy the appropriate detection or blocking mechanism before the attacker adapted and escalated.

The simulation follows the Pyramid of Pain's ascending indicator hierarchy — each detection forces the attacker to invest more time, effort, and cost to continue operating.

**Available PicoSecure Toolkit:**

* **Malware Sandbox** — Dynamic analysis engine for submitted samples
* **Manage Hashes** — EDR signature manager for hash-based blocking
* **Firewall Rule Manager** — Host-based firewall for IP-level blocking
* **DNS Filter** — Domain-level filtering and blocking
* **Sigma Rule Builder** — Behavioral detection rule authoring, mapped to MITRE ATT&CK

---

## 2. Level 1 — Hash Values

### 2.1 Sandbox Analysis: sample1.exe

I submitted `sample1.exe` to the Malware Sandbox for dynamic analysis. The report returned the following:

**General Info:**

| Field | Value |
| :--- | :--- |
| File Type | PE32+ executable (GUI) x86-64, MS Windows |
| File Size | 202.50 KB |
| Tags | `Trojan.Metasploit.A` |
| MD5 | `cbda8ae000aa9cbe7c8b982bae006c2a` |
| SHA1 | `83d2791ca93e58688598485aa62597c0ebbf7610` |
| SHA256 | `9c550591a25c6228cb7d74d970d133d75c961ffed2ef7180144859cc09efca8c` |

**Behaviour Analysis:**

| Category | Finding |
| :--- | :--- |
| MALICIOUS | Metasploit payload detected |
| SUSPICIOUS | Connects to unusual port |
| INFO | Reads machine GUID from registry |
| INFO | Checks LSA protection status |
| INFO | Reads computer name; checks supported languages |

**Analysis:** The `Trojan.Metasploit.A` tag identifies this as a Meterpreter reverse shell stager. Its sole function at this stage is to establish a C2 channel back to the attacker's machine. The INFO-level registry reads (GUID, computer name, language, LSA) are consistent with Meterpreter's standard session initialization — automated victim profiling prior to receiving further instructions.

### 2.2 Detection Applied

I submitted the SHA256 hash to the **Manage Hashes** EDR manager to block the file from executing.

```
SHA256: 9c550591a25c6228cb7d74d970d133d75c961ffed2ef7180144859cc09efca8c
```

SHA256 was selected over MD5 and SHA1 given its superior collision resistance as the current NIST standard. That said, at this level of the pyramid the choice of hash algorithm is secondary — all three are trivially defeated by a single-byte change to the file.

**Attacker Response:** Sphinx recompiled the malware, generating a new hash with identical functionality. The EDR rule was immediately rendered obsolete.

**MITRE:** N/A at hash level — no tactic mapping applicable.

---

## 3. Level 2 — IP Addresses

### 3.1 Sandbox Analysis: sample2.exe

`sample2.exe` carried a completely different hash across all three algorithms but was otherwise identical to sample1 in behavior. The sandbox report now exposed network activity not visible in the previous sample:

**General Info:**

| Field | Value |
| :--- | :--- |
| Tags | `Trojan.Metasploit.A` |
| MD5 | `44613b495c5b5e1faf5538b9f735ade4` |
| SHA1 | `687097e74e27fd8247c5accf94ef28e2ff5f049d` |
| SHA256 | `d76254e95e0b272f4ff8efa7f57eb0602be1fb26ef0c4b57f9eb2bce01d3a02f` |

**Network Activity:**

| PID | Process | Method | IP | URL |
| :--- | :--- | :--- | :--- | :--- |
| 1927 | sample2.exe | GET | 154.35.10.113:4444 | `http://154.35.10.113:4444/uvLk8YI32` |

**Connections:**

| Process | IP | Domain | ASN |
| :--- | :--- | :--- | :--- |
| sample2.exe | 154.35.10.113:4444 | — | Intrabuzz Hosting Limited |
| sample2.exe | 40.97.128.3:443 | — | Microsoft Corporation |
| sample2.exe | 40.97.128.4:443 | — | Microsoft Corporation |

**Analysis:** The C2 server is confirmed as `154.35.10.113` (ASN: Intrabuzz Hosting Limited). Port 4444 is the classic default Meterpreter C2 port. The two Microsoft Corporation entries are legitimate Windows telemetry — not malicious. The HTTP GET to `/uvLk8YI32` is the initial Meterpreter check-in request.

### 3.2 Detection Applied

I created a firewall rule in the **Firewall Rule Manager** to block outbound communication to the C2 server:

```
Type:           Egress
Source IP:      Any
Destination IP: 154.35.10.113
Action:         Deny
```

The egress rule was the primary control — blocking the outbound connection prevents the Meterpreter session from ever being established. An additional ingress rule blocking inbound from `154.35.10.113` was also applied as a defense-in-depth measure, preventing the C2 server from initiating connections back to the endpoint in the event of any future session establishment.

**Attacker Response:** Sphinx provisioned a new IP address through a cloud provider, rendering the firewall rule ineffective. The domain infrastructure remained unchanged.

**MITRE:** Command and Control **(TA0011)**

---

## 4. Level 3 — Domain Names

### 4.1 Sandbox Analysis: sample3.exe

`sample3.exe` introduced a new malicious behavior and clearly exposed the attacker's domain infrastructure:

**General Info:**

| Field | Value |
| :--- | :--- |
| Tags | `Trojan.Metasploit.A` |
| MD5 | `e31f0c62927d9e5d456c3c4049cc4bbc` |
| SHA1 | `e923d0e4b3eb295f1d065b85b1cba807ca75f13316cb085a7b` |
| SHA256 | `ac80b1268bc88e886af4ea8a141264b3bc6b9ba23f76f3f88db3df9da1a040d3` |

**Behaviour Analysis — New Malicious Indicator:**

| Category | Finding |
| :--- | :--- |
| MALICIOUS | Metasploit payload detected |
| MALICIOUS | Downloads executable files from the Internet (`backdoor.exe`, PID 2712) |
| SUSPICIOUS | Connects to unusual IP address |
| SUSPICIOUS | Connects to unusual port |

**Network Activity:**

| PID | Process | Method | IP | URL |
| :--- | :--- | :--- | :--- | :--- |
| 1021 | sample3.exe | GET | 62.123.140.9:1337 | `http://emudyn.bresonicz.info:1337/kzn293ia` |
| 1021 | sample3.exe | GET | 62.123.140.9:80 | `http://emudyn.bresonicz.info/backdoor.exe` |

**DNS Requests:**

| Domain | IP |
| :--- | :--- |
| services.microsoft.com | 40.97.128.4 |
| emudyn.bresonicz.info | 62.123.140.9 |

**Analysis:** `sample3.exe` is now functioning as a dropper — it establishes C2 contact and downloads a second-stage payload (`backdoor.exe`) onto the victim machine. The C2 domain is `emudyn.bresonicz.info`, resolving to `62.123.140.9` (ASN: Xplorita Cloud Services). The attacker switched from port 4444 to ports 1337 and 80, but the domain remained constant — that consistency is the exploitable weakness at this level.

`services.microsoft.com` is legitimate Microsoft traffic and was excluded from the investigation.

### 4.2 Detection Applied

I created a rule in the **DNS Filter** to block the C2 domain:

```
Rule Name:   Block Malware C2 server
Category:    Malware
Domain Name: emudyn.bresonicz.info
Action:      Deny
```

Denying the domain at the DNS layer blocks resolution regardless of the IP it resolves to — the malware cannot phone home even if Sphinx rotates his server infrastructure behind the same domain.

**Attacker Response:** Sphinx registered a new domain, modifying his DNS records accordingly. He acknowledged this caused him real cost and effort — purchasing and configuring domain infrastructure is significantly more friction than recompiling code or spinning up a new IP.

**MITRE:** Command and Control **(TA0011)** — T1071 (Application Layer Protocol)

---

## 5. Level 4 — Host Artifacts

### 5.1 Sandbox Analysis: sample4.exe

`sample4.exe` was the most dangerous sample encountered to this point, introducing active defense evasion and a new Registry Activity section in the sandbox report:

**General Info:**

| Field | Value |
| :--- | :--- |
| Tags | None |
| MD5 | `5f23ff13e09fe244eef5815ca01ae631` |
| SHA1 | `cd52d330f7f00ee30e33105e9f0433f4564` |
| SHA256 | `a80cff540bca65c1a28972e50d885820be7692f715c078bedce194d34d44b622` |

**Behaviour Analysis — New Malicious Indicators:**

| Category | Finding |
| :--- | :--- |
| MALICIOUS | Disables Windows Defender Real-time monitoring |
| MALICIOUS | Downloads executable files from the Internet (`backdoor.exe`, PID 1367) |
| SUSPICIOUS | Connects to unusual IP address / port |
| SUSPICIOUS | Makes changes to the registry |

**Network Activity:**

| Domain | IP | ASN |
| :--- | :--- | :--- |
| cranes0ft.iniware.xyz | 102.23.20.118 | Xplorita Cloud Services |

**Registry Activity:**

| Process | Operation | Registry Key | Name | Value |
| :--- | :--- | :--- | :--- | :--- |
| sample4.exe (PID 3806) | Write | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection` | `DisableRealtimeMonitoring` | `1` |
| explorer.exe (PID 1938) | Write | `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` | `EnableBalloonTips` | `1` |
| notepad.exe (PID 9876) | Read | `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts.txt` | `ProgId` | `txtfile` |

**Analysis:** The first registry modification is the critical finding — `sample4.exe` is deliberately setting `DisableRealtimeMonitoring = 1` under the Windows Defender Real-Time Protection key, effectively blinding the host's primary defense before proceeding with any further activity. This is MITRE T1562.001 (Impair Defenses: Disable or Modify Tools). The `explorer.exe` and `notepad.exe` registry events are normal Windows behavior and were excluded.

The new C2 domain `cranes0ft.iniware.xyz` confirms Sphinx rotated infrastructure as promised.

### 5.2 Detection Applied

I built a Sigma rule in the **Sigma Rule Builder** targeting the registry modification:

```
Log Source:    Sysmon Event Logs
Event Type:    Registry Modifications (Event ID 4663)
Registry Key:  HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
Registry Name: DisableRealtimeMonitoring
Value:         1
ATT&CK ID:     Defense Evasion (TA0005)
```

**Generated Sigma Rule:**

```yaml
title: Modification of Windows Defender Real-Time Protection
id: windows_registry_defender_disable_realtime
description: |
  Detects modifications or creations of the Windows Defender Real-Time Protection
  DisableRealtimeMonitoring registry value.

references:
  - https://attack.mitre.org/tactics/TA0005/

tags:
  - attack.ta0005
  - sysmon

detection:
  selection:
    EventID: 4663
    ObjectType: Key
    ObjectName: 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection'
    NewValue: 'DisableRealtimeMonitoring=1'

  condition: selection

falsepositives:
  - Legitimate changes to Windows Defender settings.

level: high
```

Sysmon was selected as the log source because Event ID 4663 captures object access events at the registry key level — precisely what is needed to observe this write operation. The rule targets the specific key and value combination that the malware *must* touch to achieve its defensive evasion objective. No legitimate software modifying this key should be treated as benign without explicit verification.

**MITRE:** Defense Evasion **(TA0005)** — T1562.001 (Impair Defenses: Disable or Modify Tools)

---

## 6. Level 5 — Network Artifacts

### 6.1 Log Analysis: outgoing_connections.log

With `sample5.exe`, Sphinx confirmed that all control logic now resided on his back-end server — he could freely rotate host artifacts and protocol types. The indicator was no longer in the malware file itself but in the pattern of network behavior it generated. Sphinx provided the outbound connection log from the victim machine over a 12-hour window for correlation.

**Excerpt from outgoing_connections.log:**

```
2023-08-15 09:00:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 09:23:45 | Source: 10.10.15.12 | Destination: 43.10.65.115 | Port: 443 | Size: 21541 bytes
2023-08-15 09:30:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 10:00:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
2023-08-15 10:14:21 | Source: 10.10.15.12 | Destination: 87.32.56.124 | Port: 80  | Size: 1204 bytes
2023-08-15 10:30:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
...
2023-08-15 21:00:00 | Source: 10.10.15.12 | Destination: 51.102.10.19 | Port: 443 | Size: 97 bytes
```

**Analysis:** The traffic to `51.102.10.19` exhibits three simultaneous anomalies that together constitute a definitive C2 beaconing signature:

* **Regularity:** Connections occur precisely every 30 minutes (1800 seconds) for 12 consecutive hours — 09:00, 09:30, 10:00, 10:30, and so on without exception.
* **Consistent payload size:** Every single packet is exactly 97 bytes. No variation whatsoever — consistent with an automated "alive" heartbeat, not human-generated traffic.
* **Single destination:** Every 97-byte, 30-minute connection goes to the same IP on the same port. All other connections in the log show varied IPs, varied sizes, and irregular timing — normal application behavior.

No other entry in the log shares this pattern. The combination of fixed interval + fixed size + single destination is the fingerprint of an automated C2 beaconing process.

### 6.2 Detection Applied

I built a second Sigma rule targeting the beaconing behavior pattern:

```
Log Source:         Sysmon Event Logs
Event Type:         Network Connections (Event ID 3)
Remote IP:          Any
Remote Port:        Any
Size (bytes):       97
Frequency (secs):   1800
ATT&CK ID:          Command and Control (TA0011)
```

**Generated Sigma Rule:**

```yaml
title: Alert on Suspicious Beacon Network Connections
id: network_connections_criteria_sysmon
description: |
  Detects network connections with specific criteria in Sysmon logs:
  remote IP, remote port, size, and frequency.

references:
  - https://attack.mitre.org/tactics/TA0011/

tags:
  - attack.ta0011
  - sysmon

detection:
  selection:
    EventID: 3
    RemoteIP: '*'
    RemotePort: '*'
    Size: 97
    Frequency: 1800 seconds

  condition: selection

falsepositives:
  - Legitimate network traffic may match this criteria.

level: high
```

Remote IP and Remote Port were deliberately left as `Any`. Hardcoding `51.102.10.19` or port `443` would reduce this rule to IP-level detection — trivially defeated by infrastructure rotation. The true detection value is the behavioral signature: a 97-byte packet transmitted every 1800 seconds. That rhythm is baked into the C2 framework's scheduling logic and cannot be changed without rewriting the tool itself. In a real SIEM deployment, this rule fires on the *pattern* of repeated connections matching these parameters, not on any single connection event.

**MITRE:** Command and Control **(TA0011)** — T1071, T1571 (Non-Standard Port)

---

## 7. Level 6 — Tools / Level 7 — TTPs

### 7.1 Log Analysis: commands.log

At this stage, Sphinx acknowledged that the detection cost had exceeded the engagement's value — he indicated he would need to build or acquire an entirely new tool to continue. Before disengaging, he provided the recorded command logs from all previous samples showing his post-compromise methodology on victim machines.

**commands.log:**

```
dir c:\ >> %temp%\exfiltr8.log
dir "c:\Documents and Settings" >> %temp%\exfiltr8.log
dir "c:\Program Files\" >> %temp%\exfiltr8.log
dir d:\ >> %temp%\exfiltr8.log
net localgroup administrator >> %temp%\exfiltr8.log
ver >> %temp%\exfiltr8.log
systeminfo >> %temp%\exfiltr8.log
ipconfig /all >> %temp%\exfiltr8.log
netstat -ano >> %temp%\exfiltr8.log
net start >> %temp%\exfiltr8.log
```

**Analysis — Reconnaissance command breakdown:**

| Command | Purpose |
| :--- | :--- |
| `dir c:\`, `dir "c:\Documents and Settings"`, `dir "c:\Program Files\"`, `dir d:\` | Filesystem mapping — locating valuable data and installed software |
| `ver` | OS version enumeration — identifies which exploits or post-exploitation techniques apply |
| `systeminfo` | Full system profile dump — OS, hotfixes, hardware, domain membership |
| `ipconfig /all` | Network configuration — DNS servers, domain info, network layout |
| `netstat -ano` | Active connections with PIDs — reveals other networked systems |
| `net start` | Running services enumeration — identifies security tools or exploitable services |
| `net localgroup administrator` | Local admin group membership — targets for privilege escalation or lateral movement |

The decisive finding is not any individual command but the consistent staging procedure: **every single command pipes its output into `%temp%\exfiltr8.log`**. This is Sphinx's collection procedure — a fixed methodology for aggregating reconnaissance output into a single staging file prior to exfiltration. This behavior would persist across any tool he uses, because it reflects how he personally operates, not how any specific tool functions.

### 7.2 Detection Applied

I built the final Sigma rule in the **Sigma Rule Builder** targeting the file creation event:

```
Log Source:  Sysmon Event Logs
Event Type:  File Creation and Modification (Event ID 2)
File Path:   %temp%
File Name:   exfiltr8.log
ATT&CK ID:   Collection (TA0009)
```

**Generated Sigma Rule:**

```yaml
title: Alert on Potential Exfiltration through File Creation or Modification
id: sysmon_file_creation_modification_temp
description: |
  Detects file creation or modification events with specific criteria:
  file path and file name.

references:
  - https://attack.mitre.org/techniques/TA0010/

tags:
  - attack.ta0010
  - attack.exfiltration
  - attack.file_creation
  - attack.file_modification
  - sysmon

detection:
  selection:
    - EventID: 2
      TargetFilename: '*\\exfiltr8.log'
      TargetPath: '*\\AppData\\Local\\Temp\\*'

  condition: selection

falsepositives:
  - Legitimate use of file creation and modification in a user's temp folder.

level: high
```

This rule detects the creation or modification of `exfiltr8.log` anywhere under `%temp%`. Sysmon Event ID 2 (File creation time changed) captures this event at the host level. The detection does not target any specific tool, payload, or network infrastructure — it targets the operator's procedure. Any future engagement by this actor, regardless of tooling, that follows the same collection methodology will trigger this rule.

**MITRE:** Collection **(TA0009)** — T1119 (Automated Collection), T1074 (Data Staged)

---

## 8. Implications for a SOC Analyst

This engagement provided hands-on validation of why detection maturity matters. Each level of the Pyramid of Pain produced a concrete outcome:

**Full Pyramid Coverage Summary:**

| Level | Tool | IOC Detected | Attacker Cost |
| :--- | :--- | :--- | :--- |
| Hash Values | Manage Hashes | SHA256 of `sample1.exe` | Trivial — recompile |
| IP Addresses | Firewall Manager | C2 server `154.35.10.113` | Easy — new IP |
| Domain Names | DNS Filter | `emudyn.bresonicz.info` | Annoying — new domain registration |
| Host Artifacts | Sigma / Sysmon | `DisableRealtimeMonitoring` registry write | Very annoying — technique rewrite |
| Network Artifacts | Sigma / Sysmon | 97-byte beacon every 1800 seconds | Costly — new tool required |
| TTPs | Sigma / Sysmon | `exfiltr8.log` collection procedure | Game over — actor disengaged |

The investigation reinforces that hash and IP blocking are necessary but insufficient as a primary detection strategy. Both are trivially defeated and should be treated as initial triage mechanisms, not detection anchors. The detections that caused the attacker to disengage were entirely behavioral — a registry key write, a network traffic pattern, and a file creation procedure — none of which required knowing anything about the specific tool, hash, or infrastructure in use.

From a SOC engineering perspective, the most durable detections in this engagement were those that targeted *what the attacker must do* rather than *what they used*. Disabling Defender, establishing a persistent beacon, and staging collected data are procedural constants that survive tool rotation, infrastructure changes, and recompilation. Building a detection library at this level is what separates a reactive security posture from a proactive one.

All Sigma rules were mapped to the MITRE ATT&CK framework (TA0005, TA0009, TA0011), ensuring that when any of these rules fire in a production SIEM, the responding analyst has immediate tactic-level context to guide their investigation.

---

*End of Lab Report.*