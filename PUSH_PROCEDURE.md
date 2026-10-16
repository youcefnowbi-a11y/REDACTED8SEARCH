# PUSH PROCEDURE — this repo, this host

**Read this before any `git push` in this workspace. A bare `git push` HANGS.**

## The defect

`C:/Program Files/Git/etc/gitconfig` sets `credential.helper=manager` at **system scope**
(Git for Windows installer default). The `manager` helper spawns an interactive credential
UI. With no terminal attached it **retries forever with no output**.

```
HTTP/1.1 401 Unauthorized
Server: GitHub-Babel/3.0
```

The token is **valid** — verified against the API: `youcefnowbi-a11y`, `push=True`, `admin=True`.
**The helper chain cannot reach it.**

## What does NOT work (four attempts, all failed)

- `git config --local credential.helper ""` then `--add store` — system entry persists
- `git config --global credential.helper ""` then `store` — system entry still runs first
- `git config credential.https://github.com.helper store` — per-host override, still hangs
- `--unset-all` at every writable scope — system scope is not writable as this user

Git runs **every** helper in the chain. A later `store` does not stop an earlier `manager`.

## What WORKS

```powershell
$r="C:\Users\PC\OneDrive\Desktop\FOR REDDACTED"
Set-Location $r
# token is NOT stored in this repo. Read it from the environment or a gitignored file.
$tok=$env:GH_TOKEN        # or: Get-Content "$env:USERPROFILE\.gh_token" -Raw
$url="https://youcefnowbi-a11y:$tok@github.com/youcefnowbi-a11y/REDACTED8SEARCH.git"
$env:GIT_TERMINAL_PROMPT=0
git -c credential.helper= push $url main
```

**DO NOT paste the token into a tracked file.** GitHub Push Protection (`GH013`) blocks the push at
`refs/heads/main` and names the file and line. This was hit once, on this file, in round 18 —
the rule worked, and the leak was the Lead's own. **A documented procedure that survives by quoting
the secret is not a procedure, it is a second copy of the secret.**

The `-c credential.helper=` **inline override** is the load-bearing part — it clears the chain for
that one invocation.

## Verify (never trust the push output alone)

```powershell
git rev-parse HEAD
git ls-remote origin HEAD          # must match
git ls-tree -r --name-only HEAD | Select-String 'D3[0-9]_'   # confirm files ARE in the commit
```

## Diagnosing a hang, if this recurs

```powershell
$env:GIT_CURL_VERBOSE=1
git push origin main 2>&1 | Select-Object -First 60
```

`401 Unauthorized` = credential problem (this file).
Silent with no request = network.
`GIT_TERMINAL_PROMPT=0` **suppresses the prompt AND the error** — drop it when diagnosing.

## Two related instrument traps hit the same round

1. **`git rev-list --count origin/HEAD..HEAD` returned 0 files / 0 commits** and was read as
   *"nothing to push."* **`origin/HEAD` does not resolve in this repo**, so the range was empty.
   Measure the delta against the **actual remote SHA**:
   `git diff --name-only 0893e35..HEAD`
2. **A hung instrument and a false zero are the same defect.** Both report "nothing happening."
   The remedy in both cases: **make the instrument show its work.**

## GitHub Push Protection caught a real leak — written by the Lead, in this file

The first version of this file **quoted the live token** as a working example. The push was **declined**:

```
remote: error: GH013: Repository rule violations found for refs/heads/main.
remote: - GITHUB PUSH PROTECTION
remote:     - Push cannot contain secrets
remote:       —— GitHub Personal Access Token ——————————————————————
remote:        locations:
remote:          - commit: 2e763db0a296fd78e9211ce3e27cd3bfc3fed9ba
remote:            path: PUSH_PROCEDURE.md:33
```

**The control worked.** It named the commit, the file, and the line, and refused the push.

**Resolution:** token removed from the file, `git commit --amend` so **it never entered history**, then
verified three ways:

```powershell
git grep -l $tok HEAD                      # tree     -> clean
git log --all --oneline -S $tok            # history  -> clean
# plus a recursive working-tree scan       # wd       -> clean
git ls-tree -r --name-only HEAD            # files present; push accepted  902d035..3a1729b
```

**The lesson, and it generalises past git:** *a documented procedure that survives by quoting the secret
is not a procedure, it is a second copy of the secret.* **The token is now read from `$env:GH_TOKEN` or
`$env:USERPROFILE\.gh_token` and appears in no tracked file.**

**Operational consequence: amend, do not add a fixup commit.** Once a secret is in a pushed commit it is
in the remote's reflog for everyone with read access. **This push was declined, which is the only reason
amending was sufficient — had Push Protection not existed, the leak would have shipped silently, because
nothing else in the workflow looks inside a `.md` file.**
