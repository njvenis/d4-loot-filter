# D4 Loot Filter Profile Manager

A personal, locally-hosted web tool for managing Diablo 4 loot filter profiles. Stores reusable profiles and compiles them into a rule checklist you follow while clicking through the in-game filter UI.

## Usage

Open `index.html` in a browser. No server, no install, no dependencies.

## Features

- Create, clone, and delete filter profiles
- Per-class affix, unique, and talisman set selection
- Item power threshold, Greater Affix filter (0-4), Ancestral-only toggle
- Compiles profiles into numbered rule checklists matching D4's in-game UI labels
- Enforces D4's 25-rule cap
- Copy rules to clipboard as plain text
- Profiles persist in localStorage

## Supported classes

Warlock, Paladin (more can be added to the seed JSON)

## Constraints

- Single self-contained HTML file, no build step
- Vanilla JS, no frameworks
- No backend, no external network calls
- Works fully offline
