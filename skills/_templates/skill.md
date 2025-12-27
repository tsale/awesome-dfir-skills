---
# Skill metadata (keep this at the top)
id: ""
name: ""
description: ""
version: "0.1.0"
author: ""
license: "Apache-2.0"
tags: []
# One of: triage | collection | analysis | hunting | reporting | misc
category: "misc"
# Target environments/tools (freeform)
platforms: []
inputs:
  - name: ""
    description: ""
    required: true
outputs:
  - name: ""
    description: ""
---

# {{name}}

## What this skill does

1. 
2. 
3. 

## When to use

- 

## Safety / privacy notes

- Redact secrets, tokens, personal data (PII), credentials, customer names.
- Prefer hashes and sample snippets over full dumps.

## Skill prompt (copy/paste)

> **Role**: You are a DFIR analyst.
>
> **Task**: 
>
> **Constraints**:
> - If you aren’t sure, say so and ask for the missing artifact.
> - Don’t hallucinate hostnames/users/paths.
> - Keep a clear chain of evidence and timestamp assumptions.
>
> **Provided artifacts**:
> - 
>
> **Deliverables**:
> - 

## Workflow (optional)

- Step 1:
- Step 2:

## Helper files (optional)

- `helpers/` (parsers, regex, Sigma/KQL examples, etc.)

## Compatibility notes

- Claude Skills: store this file as the skill body; keep YAML metadata.
- OpenAI/Codex Skills: use the “Skill prompt” section as the skill instructions.
