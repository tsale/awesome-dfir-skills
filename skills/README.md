# Skills catalog

This folder contains reusable DFIR / incident response “skills”: prompts, workflows, and helper files you can drop into your investigations.

## Structure

- Each skill lives in its own folder: `skills/<category>/<skill-id>/`
- The primary entrypoint is `skill.md` (with YAML metadata frontmatter)
- Optional helpers go in `helpers/` (regex, queries, parsers, etc.)

## Categories

- `triage/` — quick first-hour actions and scoping
- `collection/` — evidence collection and acquisition workflows
- `analysis/` — deep dives (timeline, malware triage, forensics)
- `hunting/` — detection engineering and hypothesis-driven hunts
- `reporting/` — writeups, executive summaries, IOC packages
- `misc/` — everything else

## Adding a new skill

1. Copy the template in `skills/_templates/skill.md`
2. Create a folder: `skills/<category>/<skill-id>/`
3. Add `skill.md`
4. (Optional) Add helpers under `helpers/`

Keep skills:
- tool-agnostic where possible
- explicit about inputs/outputs
- safe by default (privacy + evidence handling)
