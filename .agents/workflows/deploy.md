---
description: Commit, push, and monitor GitHub Actions — fix failures and retry until green
---

// turbo-all

## Steps

1. Stage all changes and commit:
```bash
cd /Users/narduk/new-code/circuit-breaker-online
git add -A
git status
```

2. Commit with a descriptive message (adjust message as needed):
```bash
git commit -m "<conventional commit message>"
```

3. Push to current branch:
```bash
git push
```

4. Watch the GitHub Actions run (wait for it to complete):
```bash
gh run watch --exit-status
```
   - If `gh run watch` exits **0** → the run passed. Skip to step 7.
   - If it exits **non-zero** → a job failed. Continue to step 5.

5. View the failed job logs to diagnose the issue:
```bash
gh run view --log-failed | tail -80
```

6. Fix the failure locally:
   - Apply the necessary code or config fix.
   - Return to **step 1** and repeat.

7. Report success to the user.
