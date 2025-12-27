# awesome-dfir-skills

A community-driven collection of DFIR / incident response **skills**: reusable prompts, workflows, and helper files that help practitioners move faster and stay consistent.

## How to use these skills (quick)

- Use these skills as **repeatable instructions**.
- Tell your assistant which skill/workflow you want to run, then provide the requested inputs/artifacts.
- Keep placeholders like `{{time_window}}` / `{{event_snippets}}` as placeholders—provide your values in the corresponding sections when prompted.
- Iterate by pasting the follow-up artifacts the skill asks for.

Browse categories and conventions in `skills/README.md`.

This repo is inspired by:

- Claude Skills: https://support.claude.com/en/articles/12512176-what-are-skills
- OpenAI/Codex Skills: https://developers.openai.com/codex/skills/

## What’s a “skill” here?

In this repository, a **skill** is a small, reusable artifact you can copy/paste into your AI assistant or IR playbook to get high-quality, repeatable outputs.

Each skill is designed to:

- state clear **inputs** and expected **outputs**
- avoid hallucinations by being explicit about unknowns
- be safe-by-default (privacy, evidence handling)

## Repository layout

- `skills/` — the catalog (organized by category)
	- `skills/<category>/<skill-id>/skill.md` — the skill entrypoint
	- `skills/<category>/<skill-id>/helpers/` — optional query snippets, regex, parsers
	- `skills/_templates/skill.md` — template for new skills

Start browsing at `skills/README.md`.

## How to use

### Claude

- Skills are folders of instructions/resources that Claude can load dynamically.
- Use the skill’s **Skill prompt (copy/paste)** as the workflow instructions, and provide your inputs in-chat when prompted.
- Keep placeholders as placeholders; provide values in the corresponding sections.

### OpenAI / Codex

- Codex skills are loaded from a skills folder (e.g., `$REPO_ROOT/.codex/skills`) and can be invoked explicitly (via skill mention) or implicitly.
- This repo stores skills under `skills/` for humans; if you want Codex to auto-load them, mirror/link them into a Codex skill location.
- Provide your artifacts/notes as inputs; keep placeholders (`{{...}}`) as placeholders.

## Contributing

Contributions are welcome—new skills, improvements, and helper files.

- Copy `skills/_templates/skill.md`
- Add your skill under `skills/<category>/<skill-id>/`
- Keep it practical, tool-agnostic where possible, and tested on real(istic) artifacts

If you’d like, I can add a simple metadata validator and contribution guidelines next.
