---
name: sync-upstream
description: Fetch the upstream amneziawg-go repository, surface what changed since this fork last synced, and help merge it in while flagging conflicts in the proxy/outline glue. Use when pulling in upstream updates or checking how far this fork has drifted.
---

# sync-upstream

This is a fork of upstream `amneziawg-go`. The goal is to stay mergeable: pull upstream changes in cleanly and keep fork-specific logic isolated (mostly `outline/`).

## Steps

1. Ensure the upstream remote exists (the fork's `origin` points at the proxy repo):
   ```bash
   git remote -v
   ```
   If there's no `upstream`, add it:
   ```bash
   git remote add upstream https://github.com/amnezia-vpn/amneziawg-go.git
   ```

2. Fetch upstream without merging:
   ```bash
   git fetch upstream
   ```

3. Show what's new and where it lands relative to this fork's `master`:
   ```bash
   git log --oneline master..upstream/master
   git diff --stat master upstream/master
   ```
   Summarize the upstream changes for the user before touching anything.

4. Flag risk areas: any upstream commits touching files this fork has modified — especially `device/`, `conn/`, `tun/` — plus anything overlapping with `outline/`. List these so the user knows where conflicts are likely.

5. Only merge after the user confirms. Prefer a feature branch:
   ```bash
   git switch -c sync/upstream-$(git -C . rev-parse --short upstream/master)
   git merge upstream/master
   ```
   Resolve conflicts keeping fork glue intact, then run the `build-verify` skill before proposing a PR.

## Notes

- Never force-push or rewrite `master`.
- If the user is unsure of the upstream URL, confirm it before adding the remote — do not guess a different org.
