---
name: commit-pr
description: Stage changes, write a conventional-commit message, branch off master, and open a squash-ready PR via gh. User-triggered with /commit-pr.
disable-model-invocation: true
---

# commit-pr

Take the current working-tree changes and turn them into a PR following this repo's conventions. Optional `$ARGUMENTS` is a hint for the PR title/scope.

## Steps

1. Review what's changing:
   ```bash
   git status
   git diff
   ```
   Run the `build-verify` skill first if it hasn't been run for these changes.

2. Create a branch off `master` (never commit straight to `master`). Name it for the change, e.g. `fix/keepalive-padding` or `feat/outline-fallback`.

3. Stage and commit with a conventional-commit message (`feat:`, `fix:`, `chore:`, `refactor:`). Use `$ARGUMENTS` as the subject hint if provided. End the commit body with:
   ```
   Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
   ```

4. Push and open the PR:
   ```bash
   git push -u origin <branch>
   gh pr create --base master --title "<conventional title>" --body "<summary>"
   ```
   The PR will be squash-merged, so the **PR title** must be a clean conventional-commit subject — that becomes the squash commit message. End the PR body with:
   ```
   🤖 Generated with [Claude Code](https://claude.com/claude-code)
   ```

5. Report the PR URL.

## Notes

- Confirm with the user before pushing or creating the PR — these are outward-facing.
- Keep changes isolated to preserve upstream mergeability (see CLAUDE.md).
