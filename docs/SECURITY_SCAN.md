# AgentForge — Security Scan

**Date:** 2026-07-22
**Scope:** `src/agentforge/` (the platform's own code) + declared dependency
closure. Report-only pass from the nightly cleanup routine; fixes applied only
where trivial and obviously correct with the test suite staying green
(70 passed).

**Method:** manual review of the security-relevant surface (target HTTP client,
dashboard web server + auth gate, LLM adapters, config), a tracked-file secret
sweep, and a dependency CVE scan (`pip-audit`). External LLM/OpenRouter egress
is blocked from this sandbox by design, so nothing here reached a live model or
spent target budget — deterministic/offline only.

---

## Summary

**No high or critical findings in AgentForge's own code.** The platform is a
security *tool*, so it deliberately sends adversarial payloads at a target — that
outbound behavior is the point and is not a vulnerability. Its own attack
surface (the dashboard and the auth gate) is small and defensively coded:
constant-time credential comparison, TLS never disabled, no dynamic-code sinks,
path traversal guarded, and consistent HTML escaping of attacker-controlled text
before it reaches the DOM.

The declared dependency closure (`requirements.txt`, `requirements-deploy.txt`)
has **no known vulnerabilities**. The only CVEs `pip-audit` surfaced live in the
sandbox **base image** (system `setuptools`/`wheel`/`urllib3`/`pyjwt`), none of
which AgentForge declares or imports — see §Dependencies.

| Sev | Count | Area |
|-----|-------|------|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 0 | — |
| Low | 1 | dashboard JS-context escaping (defense-in-depth) — **fixed** |
| Info | 3 | audit-tooling gap, redirect-following, broad excepts (intentional) |

---

## Checks run

### a. Static security review (CWE/OWASP)

Grep for dynamic-code and deserialization sinks across `src/`:

```
grep -rnE 'subprocess|os\.system|\beval\(|\bexec\(|pickle|yaml\.load\(|shell=True|__import__' src/
=> (no matches)
```

- **Injection (CWE-77/78/94):** no `eval`/`exec`/`subprocess`/`os.system`/
  `shell=True`/`__import__`. Clean.
- **Unsafe deserialization (CWE-502):** no `pickle`/`yaml.load`. All inbound
  data is parsed with `json.loads`. Clean.
- **Path traversal (CWE-22):** the dashboard's only file-read endpoint pins the
  name to its basename before joining the runs dir —
  `safe = Path(name).name; p = RUNS_DIR / safe` (`web.py:245`). `..` and
  absolute paths are stripped. Clean.
- **SSRF (CWE-918):** the target client's URLs are built from operator config
  (`cfg.base_url` / `cfg.public_base`), not from request input — there is no
  attacker-supplied URL fetch (`target/client.py`). Clean.
- **XSS (CWE-79):** the dashboard renders run data — which includes
  attacker-controlled *target responses* — into the DOM via `innerHTML`. Every
  dynamic value (`title`, `observed`, `impact`, `rationale`, `severity`,
  `finding_id`, filenames) is passed through `esc()` (`web.py:662`), which
  escapes `& < > "`. HTML-text-context XSS is closed. See the Low finding for
  the one JS-context edge.

### b. Dependency CVE scan (`pip-audit`)

```
python -m pip_audit -r requirements.txt          => No known vulnerabilities found
python -m pip_audit -r requirements-deploy.txt   => No known vulnerabilities found
```

AgentForge's declared closure is clean. A full-environment audit
(`pip-audit` with no `-r`) flags `setuptools`, `wheel`, `urllib3`, and `pyjwt`
— all **sandbox base-image** packages that AgentForge neither declares nor
imports. Recorded here for transparency; not AgentForge findings. Details in
`docs/ATO_EVIDENCE.md` §Vulnerability scan.

### c. Secret sweep (tracked files)

```
git ls-files | xargs grep -nEi '(api[_-]?key|secret|password|token)\s*[:=]'
```

Every hit is one of: a documentation **placeholder** (`sk-...`, `sk-or-...`,
`lm-studio` in `DEPLOY.md`), a config **field name** (`config.py`), or a **test
constant** (`tests/test_target_client.py`: `password="pass"`, `api_key=""`,
`TOKEN-abc123`). **No real secret is tracked.** `.env` is untracked and listed
in `.gitignore`. Clean.

### d. Dashboard auth gate

`web.py` `_check_auth` (`web.py:301`) enforces HTTP Basic auth on the mutating
and data endpoints whenever `AGENTFORGE_WEB_USER` + `AGENTFORGE_WEB_PASSWORD`
are set, comparing both fields with `hmac.compare_digest` (constant-time,
resists timing oracles) and returning `401` + `WWW-Authenticate` otherwise. When
the pair is unset the server prints a warning before binding a public interface
(`web.py:689`). The regression test `tests/test_web.py` for this gate stays
green. Working as designed.

### e. Transport / TLS

The target client resolves `verify` to the agent-proxy CA bundle when present,
else `SSL_CERT_FILE`, else system trust (`target/client.py:76`). **TLS is never
disabled** and the proxy is never unset — consistent with the sandbox rules.

---

## Findings

### LOW-1 — `esc()` doesn't escape `'`, and one sink is a single-quoted JS context — ✅ FIXED (2026-07-22)

> **Resolved.** `esc()` now also escapes `'` → `&#39;`, and `renderRuns` no
> longer uses an inline `onclick`: run items carry `data-file`/`data-kind`
> attributes and a single delegated listener on the stable `#runs` parent
> dispatches to `openDetail`, so a filename can no longer enter a JS-string
> context at all. Original finding retained below for the record.


`src/agentforge/web.py:662` (helper) / `web.py:634` (sink)

`renderRuns` interpolates run filenames into an inline handler:
`onclick="openDetail('${c.file}','campaign')"`. The values pass through `esc()`,
which escapes `& < > "` but **not** `'` — so a filename containing a single
quote would break out of the JS string literal (CWE-79, JS-context).

**Not currently exploitable:** those filenames are server-generated from fixed
patterns (`camp-<hex8>.observability.jsonl`, `probes-<hex8>.json`,
`loadtest-<hex8>.json`) with no user-controlled component, so no `'` can ever
appear. This is flagged as **defense-in-depth**: if a future change ever lets a
user name a run file, this becomes a live DOM-XSS. Not auto-fixed (touches the
escaper's contract and would want a test); logged for human review. Safe fix
when someone gets to it: add `'` → `&#39;` to `esc()`, or use
`data-file` + `addEventListener` instead of an inline `onclick`.

## Informational (no action tonight)

- **INFO-1 — CVE tooling not preinstalled.** `pip-audit`/`safety`/`bandit`
  are not in the base image; `pip-audit` was installed for this run and did
  reach the advisory DB through the proxy. If nightly runs should always scan,
  add `pip-audit` to a dev-requirements file so it's present without a network
  install.
- **INFO-2 — target client follows redirects.** `httpx.Client(...,
  follow_redirects=True)` (`target/client.py:79`). Appropriate for a pentest
  client hitting one operator-configured host; noted only so it's a conscious
  choice, not an accident.
- **INFO-3 — broad `except Exception` blocks.** Present in `_safe_json`,
  `_narrate`, `_read_json_file`, and the LLM adapters — each annotated
  `# noqa: BLE001` with a comment explaining the fail-soft intent (a malformed
  run file / LLM hiccup must never drop a report or crash the dashboard).
  Intentional, not a defect.

---

## What was fixed vs left

- **Fixed:** LOW-1 (dashboard JS-context escaping) — hardened after the nightly
  run at Adam's request; see the finding above. No high/critical findings
  existed.
- **Left:** nothing outstanding from this scan. (Mechanical lint cleanups from
  the quality phase are unrelated to these findings.)
