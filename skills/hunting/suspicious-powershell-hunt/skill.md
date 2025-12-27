---
id: "hunting.suspicious-powershell-hunt"
name: "Suspicious PowerShell hunt (cross-platform ideas)"
description: "Hypothesis-driven hunt plan for suspicious PowerShell, plus query snippets for common telemetry."
version: "0.1.0"
author: "awesome-dfir-skills contributors"
license: "Apache-2.0"
tags: ["powershell", "hunting", "lolbas", "defense-evasion"]
category: "hunting"
platforms: ["windows", "any"]
inputs:
  - name: "telemetry_stack"
    description: "What you want to query (EDR, Sysmon, Windows Event Logs, MDE, Splunk, Sentinel, Elastic)."
    required: true
  - name: "time_window"
    description: "Start/end time and timezone."
    required: true
outputs:
  - name: "hunt_plan"
    description: "Prioritized hypotheses + what to query + what to pivot to next."
  - name: "query_snippets"
    description: "Copy/paste query fragments (generic + some platform-specific)."
---

# Suspicious PowerShell hunt (cross-platform ideas)

## What this skill does

- Generates a structured hunt plan for PowerShell abuse.
- Focuses on signals that stay useful across tool stacks.

## When to use

- You suspect downloader/execution via PowerShell.
- You’re responding to alerts like “EncodedCommand”, “IEX”, “FromBase64String”.

## Safety / privacy notes

- Don’t paste full script blocks from production unless permitted.
- Prefer hashing script blocks or sharing key substrings.

## Skill prompt (copy/paste)

> **Role**: You are a detection engineer / threat hunter.
>
> **Task**: Build a PowerShell abuse hunt plan for the given environment and time window.
>
> **Telem stack**:
> {{telemetry_stack}}
>
> **Time window**:
> {{time_window}}
>
> **Deliverables**:
> 1) **Top hypotheses** (3–7) for PowerShell abuse in this environment
> 2) For each: **what to query**, **expected true positives**, **common false positives**, and **next pivots**
> 3) **Query snippets** (generic string/regex and, if possible, one version for the named stack)
>
> **Constraints**:
> - Prefer fields commonly present: process name, parent process, command line, parent command line, user, host, network dest.
> - If you propose a platform-specific query, explain field mapping.

## Common suspicious patterns (generic)

- `-enc` / `-encodedcommand`
- `IEX` / `Invoke-Expression`
- `FromBase64String`
- `DownloadString` / `DownloadFile`
- Hidden window: `-w hidden`
- Bypass: `-ExecutionPolicy Bypass`
- LOLBIN parents: `winword.exe`, `excel.exe`, `outlook.exe`, `mshta.exe`, `rundll32.exe`, `wscript.exe`, `cscript.exe`

## Pivots

- Process tree around the suspicious PowerShell
- PowerShell downloading things from the internet
- Network connections from that PID (destinations, SNI, URL paths)
- File writes shortly after execution
- Persistence artifacts (scheduled tasks, services, Run keys)
