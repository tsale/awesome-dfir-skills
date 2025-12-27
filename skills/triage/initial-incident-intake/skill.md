---
id: "triage.initial-incident-intake"
name: "Initial incident intake & scoping"
description: "First-hour intake checklist + questions that produce an actionable scope and evidence plan."
version: "0.1.0"
author: "awesome-dfir-skills contributors"
license: "Apache-2.0"
tags: ["triage", "case-management", "scoping", "first-hour"]
category: "triage"
platforms: ["any"]
inputs:
  - name: "intake_notes"
    description: "Freeform notes from reporter: what happened, when, where, who noticed."
    required: true
  - name: "environment_summary"
    description: "Org context: identity provider, EDR, email, cloud, logging, time zone."
    required: false
outputs:
  - name: "scoped_incident_summary"
    description: "Short summary + working hypothesis + known/unknowns + next actions."
  - name: "evidence_request_list"
    description: "Concrete list of artifacts to request/collect next."
---

# Initial incident intake & scoping

## What this skill does

- Converts messy intake notes into a clear incident statement, assumptions, and immediate next actions.
- Produces an evidence request list tailored to the suspected incident type.
- Captures “known/unknowns” and identifies the critical time window.

## When to use

- New case creation / first response.
- Handoff between SOC and IR.
- You need to quickly decide: contain now vs. observe vs. wait for more evidence.

## Safety / privacy notes

- Don’t paste raw email bodies with PII unless necessary—prefer headers and redacted snippets.
- Don’t paste credentials, secrets, access tokens.

## Skill instructions

> **Role**: You are a DFIR incident responder.
>
> **Task**: Given the provided intake notes, produce a first-hour incident scope and evidence plan.
>
> **Rules**:
> - If details are missing, ask *targeted* questions.
> - Don’t assume logging sources exist—confirm.
> - Use the reporter’s time zone; if unknown, call it out.
>
> **Provided intake notes**:
> {{intake_notes}}
>
> **Environment summary (if any)**:
> {{environment_summary}}
>
> **Deliverables**:
> 1) **Incident summary** (2–5 sentences)
> 2) **Working hypothesis** (what you think is happening + confidence)
> 3) **Time window** (earliest suspected activity → latest)
> 4) **Known / Unknown** (bullets)
> 5) **Immediate containment considerations** (safe, low-regret actions)
> 6) **Evidence / logs to request next** (prioritized, with WHY for each)
> 7) **Next 60 minutes plan** (checklist)

## Suggested intake questions

- What triggered the report (alert type, user report, anomaly)?
- What’s the impacted business function (email, HR, finance, prod)?
- Which identities/assets are suspected (usernames, hostnames, IPs)?
- Any recent “change events” (password reset, MFA changes, new admin roles)?
- What actions already taken (reimage, isolate, disable account)?

## Evidence request starter list

Pick the relevant items based on incident type:

- **Identity (Entra/AD/Okta)**: sign-in logs, audit logs, MFA events, risky sign-ins
- **Email**: message trace, headers, URL click logs, mailbox audit, rules/forwarding
- **Endpoints**: EDR detections, timeline, process tree, network connections
- **Network**: proxy/DNS logs, firewall flows, VPN logs
- **Cloud**: CloudTrail / GCP audit logs / Azure activity, object storage access logs
