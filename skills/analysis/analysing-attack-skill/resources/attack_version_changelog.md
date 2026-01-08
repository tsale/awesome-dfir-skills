# ATT&CK Version Changes (v15→v18.1)

Quick reference for deprecated, renamed, and new technique IDs. Use when analysing older reports or validating mappings.

## Technique ID Changes

| Old ID | Status | New ID | Name | Version |
|--------|--------|--------|------|---------|
| T1574.002 | MERGED | T1574.001 | DLL Side-Loading → DLL | v17 |
| T1453 | UN-DEPRECATED | T1453 | Abuse Accessibility Features (Mobile) | v18 |
| T1204.003 | NEW | — | User Execution: Malicious Copy and Paste | v17 |
| T1585.004 | NEW | — | Email Bombing | v17 |
| T1656.002 | NEW | — | Email Spoofing | v17 |

## Platform Changes

| Old Platform | New Platform | Version |
|--------------|--------------|---------|
| Azure AD | Identity Provider | v16 |
| Office 365 | Office Suite | v16 |
| Google Workspace | Office Suite | v16 |
| Network | Network Devices | v17 |
| — | ESXi (new) | v17 |

## Detection Model Change (v18)

**CRITICAL:** v18 fundamentally changed how detections are documented.

| Deprecated | Replaced By |
|------------|-------------|
| Data Sources | Detection Strategies |
| Detection notes (free text) | Analytics (1,739 structured rules) |

**New mapping chain:** Technique → Detection Strategy → Analytics → Data Components → Log Sources

**When analysing pre-v18 content:** Data Source references map to Detection Strategies. Analytics format changed from CAR pseudocode (pre-v15) → Splunk-style queries (v15-v17) → structured Analytics objects (v18).

## New Coverage Areas (v17-v18)

**v18:** CI/CD pipelines, Kubernetes, cloud databases, ransomware prep behaviours, Signal/WhatsApp linked-devices abuse, supply chain attacks

**v17:** ESXi hypervisor (34 adapted + 4 new techniques), ClickFix-style attacks, email-based social engineering

**v17 Notable Groups:** G1045 Salt Typhoon (PRC), G1044 APT42 (Iran), G1041 Sea Turtle (Türkiye), G1043 BlackByte 2.0

## Version Timeline

| Ver | Date | Key Change |
|-----|------|------------|
| v18.1 | Oct 2025 | Current - minor fixes |
| v18 | Oct 2025 | Detection model overhaul (Data Sources deprecated) |
| v17 | Apr 2025 | ESXi platform, DLL technique merge |
| v16 | Oct 2024 | Cloud platform refactor, ICS sub-techniques |
| v15 | Apr 2024 | Analytics → Splunk-style, ICS cross-mapping |

## Stats (v18.1)

Enterprise: 211 techniques, 468 sub-techniques | Groups: 170 | Software: 877 | Campaigns: 50