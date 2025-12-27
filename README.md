# awesome-dfir-skills

A community-driven collection of DFIR / incident response **skills**: reusable prompts, workflows, and helper files that help practitioners move faster and stay consistent.

## How to use these skills (quick)

- Pick a skill from `skills/` and open its `skill.md`.
- Copy the **Skill prompt (copy/paste)** into your assistant/tool (Claude, Codex, etc.).
- Replace placeholders like `{{time_window}}` / `{{event_snippets}}` with your case artifacts (sanitized).
- Run the prompt, then iterate by pasting the requested follow-up artifacts.

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

- Create a new Claude “skill” and paste the contents of a `skill.md` file.
- Keep the YAML metadata at the top; it’s useful for humans and for catalog tooling.

### OpenAI / Codex

- Use the **Skill prompt (copy/paste)** section from `skill.md` as the skill instructions.
- Fill in the placeholders (`{{...}}`) with the artifacts/notes from your case.

## Contributing

Contributions are welcome—new skills, improvements, and helper files.

- Copy `skills/_templates/skill.md`
- Add your skill under `skills/<category>/<skill-id>/`
- Keep it practical, tool-agnostic where possible, and tested on real(istic) artifacts

If you’d like, I can add a simple metadata validator and contribution guidelines next.
