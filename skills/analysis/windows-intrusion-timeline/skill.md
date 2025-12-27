---
id: "analysis.windows-intrusion-timeline"
name: "Windows intrusion timeline (targeted)"
description: "Create a targeted intrusion timeline for a Windows incident using whatever artifacts are available (event logs, EDR, SIEM exports, triage notes)."
version: "0.1.0"
author: "awesome-dfir-skills contributors"
license: "Apache-2.0"
tags: ["windows", "timeline", "intrusion", "authentication", "process-execution"]
category: "analysis"
platforms: ["windows"]
inputs:
  - name: "case_context"
    description: "Environment + scope: host roles, time window, timezone, suspected technique, what telemetry/artifacts exist (event logs, EDR, SIEM, triage notes)."
    required: true
  - name: "artifacts"
    description: "Relevant investigation artifacts (bounded): event entries (text/JSON/CSV), EDR process tree, alerts, command lines, file hashes/paths, network indicators, or short summaries with examples."
    required: true
outputs:
  - name: "timeline"
    description: "Chronological list of notable events with interpretations and confidence." 
  - name: "followup_queries"
    description: "Concrete event filters/queries to run next (by EventID and fields)."
---

# Windows intrusion timeline (targeted)

## What this skill does

- Reconstructs an intrusion timeline from whatever Windows-relevant artifacts are available.
- Highlights gaps (missing log sources, disabled auditing, clock skew).
- Produces follow-up queries (EventID + fields) to confirm hypotheses.

## When to use

- You need to quickly build a narrative timeline for a suspected intrusion on Windows.
- You’re validating lateral movement, logons, privilege changes.

## Safety / privacy notes

- Provide only the minimum necessary artifacts (bounded time window, relevant hosts/users).
- Redact usernames if required, but keep consistent pseudonyms.
- Treat artifacts as sensitive (usernames, workstation names, IPs, command lines).

## Inputs: what to provide (recommended)

To get the best timeline, provide a **"case bundle"**:

1) **Scope & environment**
  - Host role (workstation, server, DC)
  - Domain name (or redacted label), time zone, NTP/clock skew situation
  - Time window (start/end) and whether it’s in UTC or local time

2) **What telemetry / artifacts you have**
  - Windows logs: Security, System, PowerShell/Operational, Sysmon (if present), TaskScheduler, WMI, TerminalServices, etc.
  - EDR: process tree, detections, network telemetry, file operations
  - SIEM exports / forwarded events (CSV/JSON) is fine
  - Note which key fields exist (timestamp, host, user, process, command line, parent/child IDs)

3) **Artifacts (bounded)**
  - Either: a few dozen/high-signal rows/events, or summary counts + top examples
  - Prefer structured fields (JSON/CSV) over rendered message text

## Skill instructions

> **Role**: You are a Windows DFIR analyst.
>
> **Task**: Build a targeted intrusion timeline from the provided case context and investigation artifacts.
>
> **Rules**:
> - Don’t invent events. If there are gaps, call them out and explain what would fill them.
> - Normalize timestamps. If timezone is unclear, explicitly label times as “untrusted”.
> - Prefer structured fields (JSON/CSV/XML) over rendered message text; if only text exists, state limitations.
> - Track confidence per finding (High/Med/Low) with a one-line reason.
> - Separate **facts** (observed events) from **interpretation** (hypotheses).
> - If you identify a suspicious execution, **pivot** around it (parent/child relationships) and trace activity **backwards and forwards**.
>
> **Case context**:
> {{case_context}}
>
> **Artifacts**:
> {{artifacts}}
>
> **Deliverables**:
> 1) **Timeline assumptions**
>    - Timezone used, clock skew considerations, host naming assumptions (if redacted)
> 2) **Notable event timeline** as a table with columns:
>    - `time` (ISO 8601)
>    - `host`
>    - `log` (e.g., Security/System/PowerShell/Sysmon)
>    - `event_id`
>    - `actor` (user/service account; or “unknown”)
>    - `artifact` (process/service/task/account/network)
>    - `summary` (what happened)
>    - `interpretation` (why it matters)
>    - `confidence` (High/Med/Low)
> 3) **Key threads** (map events into phases: initial access → execution → persistence → privilege escalation → lateral movement → collection/exfil)
> 4) **Gaps & limitations**
>    - Missing logs (e.g., no Sysmon, no PowerShell 4104, no 4688)
>    - Missing fields (e.g., no command line, no parent process)
>    - Audit policy implications (what might be disabled)
> 5) **Follow-up queries / filters to run next**, grouped by log source
>    - Provide EventID + key fields to filter on
>    - Include 1–2 examples per log source
> 6) **Recommended next artifacts** to collect to validate each key hypothesis
>    - e.g., Sysmon config, Amcache, Prefetch, SRUM, Shimcache, scheduled tasks export, services list, browser history, EDR telemetry

## Pivoting guide: trace a suspicious execution chain

Use this procedure whenever the incident involves a suspicious process/script/service/task.

1) **Select a seed “suspicious event”**
  - Pick one event in the provided data that looks most suspicious (e.g., unusual parent process, encoded PowerShell, LOLBIN usage, new service, scheduled task).
  - If the provided snippets do not include a clearly suspicious event, **request it**:
    - ask for one representative process execution or persistence event (including timestamp, host, user, image, command line, parent, and any IDs/guids/pids).

2) **Extract pivot keys from the seed** (use whatever is available)
  - time window: $T_{seed} \pm$ 5–30 minutes (expand as needed)
  - host, user, log/channel
  - process identifiers: PID, ProcessGuid, LogonId, TargetUser, service name, task name
  - image path + command line substrings

3) **Trace backwards (how did it start?)**
  - Look for the **parent process** and the events immediately preceding execution.
  - Identify the initial launcher (Office → script, browser → dropper, service → binary, WMI → process, etc.).
  - Look for authentication context changes (new logon, special privileges, remote logon types).

4) **Trace forwards (what did it do next?)**
  - Enumerate **child processes spawned** by the suspicious process and their command lines.
  - Correlate network connections, file writes, registry changes, services/tasks creation.
  - If multiple hosts appear, note potential lateral movement and the pivot needed (user/IP/logon session).

5) **If Sysmon data exists, prioritize these correlations**
  - **Process creation**: Sysmon **Event ID 1** for parent/child chains and command lines.
  - **Network**: Sysmon **Event ID 3** for destinations contacted by the suspicious process and its children.
  - **File creation**: Sysmon **Event ID 11** for payload drops, staging, and script writes correlated to the same process chain.
  - **Process injection (if present in your dataset/config)**:
    - look for Sysmon injection-related events (commonly **Event ID 8** “CreateRemoteThread”, and/or other injection telemetry depending on configuration)
    - correlate *source process* (injector) → *target process* (injected) → follow child/network/file activity from both

6) **Ask for the next best missing pivot**
  - If parent/child relationships can’t be established from the provided artifacts, ask specifically for:
    - Sysmon EID 1 around the seed time window, or
    - Security 4688 (process creation) if enabled, or
    - EDR process tree export for the involved host/time.

## Output guidance (so timelines are consistent)

- Prefer a single unified timeline sorted by time; if multi-host, include host for every row.
- Use one of the following confidence patterns:
  - **High**: directly evidenced by event + supporting fields (e.g., logon type, process ID, command line)
  - **Med**: event suggests activity but key fields are missing
  - **Low**: inference based on weak/indirect indicators

## Follow-up query patterns (generic)

When you propose follow-ups, express them as:

- **Log**: Security
  - **EventID(s)**: 4624
  - **Filter fields**: `TargetUserName`, `IpAddress`, `LogonType`, `AuthenticationPackageName`, `WorkstationName`
  - **Purpose**: confirm interactive vs network logons, source IPs, pivot users/hosts

## Helpful EventIDs (starter)

- Security: 4624/4625 (logon success/fail), 4634 (logoff), 4672 (special privileges)
- Security: 4720/4722/4723/4724/4725/4726 (user lifecycle), 4728/4732/4756 (group changes)
- Security: 7045 in System (service installed) (note: 7045 is System log)
- PowerShell: 4104 (script block) if enabled
- Sysmon: 1 (process), 3 (network), 7 (image load), 11 (file create), 13 (registry set)
