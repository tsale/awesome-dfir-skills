---
# Skill metadata (keep this at the top)
name: ""
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

## Skill instructions

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

- Claude Skills: store the instructions in the skill file; keep YAML metadata.
- OpenAI/Codex Skills: use the “Skill instructions” section as the skill instructions.
