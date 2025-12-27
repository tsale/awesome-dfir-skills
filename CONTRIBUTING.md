# Contributing

Thanks for contributing to **awesome-dfir-skills**.

## What belongs in this repo

A “skill” is a reusable DFIR / incident response artifact:

- a prompt that produces consistent outputs (with clear inputs/outputs)
- a small workflow/checklist
- helper files (queries, regex, parsers, mapping tables)

## Quick start

1. Pick a category under `skills/` (or propose a new one).
2. Copy the template: `skills/_templates/skill.md`
3. Create a new folder: `skills/<category>/<skill-id>/`
4. Add `skill.md`
5. (Optional) Add `helpers/` with supporting files and examples.

## Style guidelines

- **Be explicit about assumptions.** If a log source may not exist, say so.
- **Declare inputs and outputs.** Use the YAML frontmatter.
- **Keep it bounded.** Prefer targeted snippets and time windows.
- **Safety-first.** Call out privacy/evidence handling.
- **Tool-agnostic by default.** If you include Splunk/KQL/Elastic examples, label them and explain field mapping.

## Naming

- `skill-id` should be lowercase, kebab-case.
- Prefer action-oriented names, e.g. `initial-incident-intake`.

## Licenses

- Repo is Apache-2.0; contributions should be compatible with Apache-2.0.
- Don’t add content that you don’t have rights to share.

## Submitting changes

- Open a PR with a short description of the skill and when it’s used.
- If possible, include a tiny example input/output snippet (sanitized).
