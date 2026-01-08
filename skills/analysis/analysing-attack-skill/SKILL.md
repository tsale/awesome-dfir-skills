---
name: analysing-attack
description: Analyse Mitre ATT&CK tactics, techniques and sub-techniques. Use when performing analysis of threat detections, threat models, security risks or cyber threat intelligence
---

# Analysing ATT&CK Tactics and Techniques

## Overview

This document provides best practices and resources for use when mapping ATT&CK tactics and techniques to threat detections, threat models, security risks or cyber threat intelligence.

Contains information on v18.1 (latest) version of Mitre ATT&CK

## Available Resources

Resources folder contains LLM optimised and token-efficient content. Read whole file for broad context or grep or glob for specfic keywords or IDs. Use index files for quick reference keyword searches.

Tactics are abreviated: REC=Reconnaissance, RD=Resource Development, IA=Initial Access, EX=Execution, PE=Persistence, PRV=Privilege Escalation, DE=Defense Evasion, CA=Credential Access, DIS=Discovery, LM=Lateral Movement, COL=Collection, C2=Command and Control, EXF=Exfiltration, IMP=Impact

### Searching Examples

**By keyword (recommended for discovery)**:
```grep -i "cron\|bash\|/proc/\|cryptocurrency" resources/attack_keywords.idx```

**By technique ID (for validation)**:
```grep "T1053" resources/attack_techniques.md```

**By tactic abbreviation (find all persistance techniques)**:
```grep "PE" resources/attack_techniques.md```


### Resource Files

**ATT&CK Technique Keyword Index**: Index file for quick keyword searching to identify suitable ATT&CK IDs for further research. Sorted alphabetically and fomatted as keyword:technique_ids (comma seperated when multiple). See -> [resources/attack_keywords.idx](resources/attack_keywords.idx)

**ATT&CK Technique List**: Markdown table containing ATT&CK ID, name, keywords, description and platforms. Sorted by ID. Use when researching techniques, valdiating IDs, searching for up-to-date descriptions or filtering by platform. See -> [resources/attack_techniques.md](resources/attack_techniques.md)

**ATT&CK Version Changelog**: Reference for v15->v18.1 changes including deprecated techniques, renamed platforms, and the v18 detection model overhaul. Use when analysing older reports or understanding structural changes. See -> [resources/attack_version_changelog.md](resources/attack_version_changelog.md)

## Best Practice

Use your judgment alongside these guidelines to generate high-quality ATT&CK analysis.

- Do not assume your knowledge is 100% complete or up to date. Use the resources provided
- Carefully read any supplied information, perform deep analysis line by line if needed
- Search broadly for keywords, you may need to iterate multiple times to find every correct technique
- Think about the specific procedure being performed and consider the attacker (or defender) intent before determining appropriate tactic, technique or sub-technique
- Some techniques are part of multiple tactics (for ex. T1078 Valid Accounts) and may appear different for each tactic
- Other techniques are similar but distinct depending on tactic (for ex. T1213.003 and T1593.003 are both Code Respositories)
- Map to the most specific sub-technique when possible

### When Analysing CTI Reports

- IMPORTANT: Read the whole report fully, including tables of IOCs, appendixes or linked STIX files
- Screenshots contain valuable intelligence, ensure they are processed
- Break down the report into granular procedures when mapping to techniques
- Think about attacker objectives. What did they take that action? What did they hope to achieve?
- Avoid infering techniques that are not contained in the report
- Once initial analysis is complete, perform a second analysis to valdiate your findings and idenitify any missed techniques

### When Analysing Detections

- Detection logic may detect multiple techniques, map all that are applicable
- Analyse detection log sources and fields, these can help determine distinct tactics or techniques
- Consider the intent (hypothesis) of the detection, what was the engineers objective?

## Commonly Missed Techniques

### Command-Line Indicators
`-windowstyle hidden`|`-w hidden` -> T1564.003 Hidden Window
`-encodedcommand`|`-enc`|`base64` -> T1027.010 Command Obfuscation
`-noprofile`|`-ep bypass` -> T1059.001 PowerShell

### Encoding
Encoded payload delivered -> T1027.013 Encrypted/Encoded File
Decoded at runtime -> T1140 Deobfuscate/Decode

### RDP-Related
RDP connection|`.rdp` file -> T1021.001 Remote Desktop Protocol
Clipboard redirect -> T1115 Clipboard Data
Drive mapping|attached drives -> T1039 Data from Network Shared Drive
Auth redirect|intercept -> T1557 Adversary-in-the-Middle

### Infrastructure
DDNS|dynamic DNS|No-IP|FreeDNS -> T1568.002 Domain Generation + T1583.006 Web Services
Typosquat|lookalike domain -> T1583.001 Domains
Compromised server -> T1584.004 Server

### Network
SSH tunnel|port forward -> T1572 Protocol Tunneling
Downloaded|fetched payload -> T1105 Ingress Tool Transfer
Over port 80/443 -> T1071.001 Web Protocols

### Social Engineering
Masqueraded|posed as|impersonated -> T1656 Impersonation
Spoofed|mimicked|fake page -> T1036.005 Match Legitimate Name
Credential harvest|fake login -> T1598.003 Spearphishing Link (Recon)

### Technique Pairs
T1566 Spearphishing -> check T1204 User Execution
T1027 Obfuscation -> check T1140 Deobfuscation
T1053 Scheduled Task -> check T1059 Interpreter
T1021.001 RDP -> check T1115, T1039, T1557
T1059.001 PowerShell -> check T1564.003 Hidden Window

### Red Flag Phrases
"downloads and executes" -> T1105 + T1059
"persistence via task" -> T1053 + T1059
"C2 over HTTPS" -> T1071.001 + T1573.002
"compromised infrastructure" -> T1584.004
"redirects traffic" -> T1572 or T1090
"harvests credentials via fake page" -> T1598.003 (Recon tactic)