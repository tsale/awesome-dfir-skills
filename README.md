# 🔥 awesome-dfir-skills

> *Because incident responders shouldn't have to reinvent the wheel at 3 AM*

A community-driven collection of DFIR / incident response **skills**: reusable prompts, workflows, and helper files that help practitioners move faster, stay consistent, and maybe—just maybe—get some sleep.

---

## 🚀 Quick Start (TL;DR for the Sleep-Deprived)

1. Pick a skill from `skills/README.md`
2. Copy/paste it into your AI assistant (Claude, Codex, etc.)
3. Feed it your artifacts when prompted
4. Watch the magic happen ✨

**Pro tip:** Keep placeholders like `{{time_window}}` as-is—fill them in when the skill asks for them.

---

## 🤔 What's a "Skill" Anyway?

Think of a skill as a **cheat code for IR**. It's a small, reusable artifact you can copy/paste into your AI assistant or playbook to get consistent, high-quality outputs every time.

Each skill is designed to:

| Feature | Why It Matters |
|---------|----------------|
| 📥 Clear inputs & outputs | No guessing games |
| 🎯 Explicit about unknowns | Fewer hallucinations, more facts |
| 🔒 Safe-by-default | Evidence handling & privacy baked in |

---

## 📁 Repository Layout

```
skills/
├── README.md                          # Start here → skill catalog
├── _templates/
│   └── skill.md                       # Template for new skills
└── <category>/
    └── <skill-id>/
        ├── skill.md                   # The skill entrypoint
        └── helpers/                   # Query snippets, regex, parsers
```

---

## 🛠️ Platform Setup

### Claude Desktop / Claude.ai

Skills are folders of instructions that Claude loads dynamically:

1. Use the skill's **Skill prompt** as workflow instructions
2. Provide inputs in-chat when prompted
3. Keep `{{placeholders}}` intact—fill values in the corresponding sections

### OpenAI / Codex

Codex loads skills from a dedicated folder (e.g., `$REPO_ROOT/.codex/skills`):

1. Mirror or symlink skills from `skills/` to your Codex skill location
2. Invoke skills explicitly (mention them) or let Codex pick them up implicitly
3. Provide artifacts as inputs; keep `{{...}}` placeholders as-is

---

## 🤝 Contributing

Got a killer workflow that's saved your bacon during an incident? Share it!

### How to Add a Skill

1. Copy `skills/_templates/skill.md`
2. Create `skills/<category>/<skill-id>/skill.md`
3. Keep it practical, tool-agnostic where possible
4. Test on real (or realistic) artifacts

**Coming soon:** Metadata validator and detailed contribution guidelines.

---

## 💡 Inspiration

This project stands on the shoulders of giants:

- [Claude Skills](https://support.claude.com/en/articles/12512176-what-are-skills) — Anthropic's skill system
- [OpenAI Codex Skills](https://developers.openai.com/codex/skills/) — OpenAI's approach

---

## 📜 License

MIT — Use it, fork it, improve it. Just don't blame us if you use the wrong skill at 4 AM.

---

<p align="center">
  <strong>Made with ☕ and mild panic by the DFIR community</strong>
</p>
