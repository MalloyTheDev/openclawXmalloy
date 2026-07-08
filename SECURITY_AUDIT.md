# Fork Security & Hardening Audit

Audit of `MalloyTheDev/openclawXmalloy` (an OpenClaw fork). Goal: find bugs, wiring
issues, security issues, and hardening opportunities to help improve the fork.

**Overall verdict:** the codebase carries OpenClaw's upstream security posture and is
**well-hardened**. No externally-exploitable Critical/High vulnerability was found across
CI/CD, containers/build, supply chain, or the `src/**` runtime. Confirmed-safe defenses
include: timing-safe secret comparison in the gateway (`src/security/secret-equal.ts`),
SSRF guards with DNS pinning (`src/infra/net/ssrf.ts`), realpath-based path containment in
the media store and skill installer, thorough secret redaction, SHA-pinned GitHub Actions,
a non-root digest-pinned `Dockerfile`, and a fail-closed gateway bind
(`bind: lan` + `auth: none` → "refusing to bind gateway").

The items below are the genuine, verified findings — mostly Medium/Low hardening gaps.
Each is intended to become a GitHub issue (labels: `security` / `hardening`, plus `audit`).

## Remediation status

| # | Finding | Status |
|---|---------|--------|
| 1 | Weak 32-bit noVNC/VNC password | **Fixed** — 8 chars from full alphanumeric keyspace, SIGPIPE-safe |
| 4 | Fly template omits gateway token | **Fixed** — deploy-time `fly secrets set` guidance added |
| 6 | `.gitignore` missing signing-key patterns | **Fixed** — patterns added (0 tracked-file collisions) |
| 7a | `advisory` dispatch input interpolated into shell | **Fixed** — routed through `env:` |
| 2 | `chmod 0777` on CI secret dirs | Deferred — `0700` breaks cross-UID container reads of the mounted config; token is a throwaway CI value. Needs a `chown`-to-container-UID fix validated on CI. |
| 3 | Predictable `/tmp` HOME (TOCTOU) | Deferred — a `rm -rf $HOME` guard risks wiping a mounted browser-profile volume; single-tenant container. Needs an ownership-assert approach. |
| 5 | Missing containment in `resolveTranscriptMediaPath` | Deferred — prod hot-path change; requires full Vitest suite on Testbox (not runnable in this session) before landing. |
| 7b | `crabbox_runner_label` in `runs-on` | Deferred — `type: choice` enum needs the valid self-hosted label list. |

Fixes above are self-contained shell/config/CI changes, each syntax-validated
(`bash -n`, YAML/TOML parse, `git check-ignore`). Deferred items remain documented
below and are safe to tackle next with the appropriate validation.

---

## 1. Browser sandbox auto-generates a weak 32-bit noVNC/VNC password — Medium · `security`

**Location:** `scripts/sandbox-browser-entrypoint.sh:313-316` (generation), `:327` (exposure)

When `NOVNC_PASSWORD` is unset, the framebuffer password is a UUID truncated to **8 hex
characters (~32 bits)**. `x11vnc` is bound `-localhost`, but `websockify` bridges the live
desktop on `0.0.0.0:${NOVNC_PORT}`. If that port is ever published (the repo ships
`src/security/audit-sandbox-browser` because this happens), the desktop is reachable behind
a brute-forceable password. A VNC secret holds 8 full printable chars (~56 bits); the hex
truncation discards ~half the keyspace.

**Fix:** draw from the full printable keyspace
(`head -c 16 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 8`), and/or fail closed
(refuse to start noVNC when no explicit password is provided).

## 2. CI harness scripts `chmod 0777` directories holding the gateway auth token — Low · `security`

**Location:** `scripts/e2e/compose-setup.sh:25`, `scripts/test-live-codex-harness-docker.sh:129`, `scripts/test-install-sh-docker.sh:392`

`chmod -R 0777` is applied to config/auth-profile directories that are then populated with
`openclaw.json` containing the gateway `token`. On a shared/multi-tenant CI runner any local
user can read the token (or pre-seed/replace the config before the container mounts it).
`mktemp -d` already yields `0700`; the explicit `0777` only loosens it.

**Fix:** use `0700` on secret-bearing dirs; if a container UID needs write access,
`chown`/`chmod` to that UID rather than world-writable.

## 3. Browser sandbox uses a predictable shared `/tmp` HOME (TOCTOU on VNC password file) — Low · `security`

**Location:** `scripts/sandbox-browser-entrypoint.sh:7-9` (`HOME=/tmp/openclaw-home`), used at `:319-321`

A fixed path holds the Chrome profile and the VNC password file (`${HOME}/.vnc/passwd`).
If run outside a single-tenant container, or if a hostile local user pre-creates
`/tmp/openclaw-home`, the credential file/profile can be pre-seeded or read (TOCTOU on
`mkdir -p` over an attacker-owned directory).

**Fix:** use a per-run private dir (`HOME="$(mktemp -d /tmp/openclaw-home.XXXXXX)"`), or
assert the path is a fresh root-owned mount before writing the credential.

## 4. Public Fly.io template omits the gateway token and steers toward a public `--bind lan` — Low · `hardening`

**Location:** `fly.toml:18` (`--allow-unconfigured --bind lan`, no token) vs `render.yaml` (which sets `OPENCLAW_GATEWAY_TOKEN` via `generateValue: true`)

The Fly template exposes an HTTP service and boots the gateway unconfigured on a `lan` bind
with no token. This is **mitigated** by the runtime fail-close (verified in
`src/gateway/server-runtime-config.test.ts:168`), so the result is a broken deploy rather
than an open gateway — but it steers users toward a public bind and invites them to "fix" it
by disabling auth.

**Fix:** mirror `render.yaml` — add `OPENCLAW_GATEWAY_TOKEN` as a Fly secret, or document
that the template requires a token before it will serve.

## 5. Missing path-containment assertion in `resolveTranscriptMediaPath` (defense-in-depth) — Low · `hardening`

**Location:** `src/sessions/user-turn-transcript.ts:162-168`

`resolveTranscriptMediaPath` does a bare `path.join(workspaceDir, pathValue)` for relative,
non-URL-like values with no containment check. The result flows into the persisted transcript
and `ctx.MediaPaths`, which feeds sandbox staging / the Read tool. The normal inbound pipeline
stages media into the UUID-based store (values are store-controlled), so no attacker-settable
source was established — this is the one media-path join in the runtime lacking a local
containment guard.

**Fix:** add an explicit `isWithinDir(workspaceDir, resolved)` assertion here, matching the
containment pattern used elsewhere in the media store.

## 6. Root `.gitignore` lacks signing-key / service-account patterns (preventive) — Low · `hardening`

**Location:** `.gitignore`

`*.p8`, `*.p12`, `*.pem`, `*.key`, and `google-play-service-account.json` are **not** ignored,
while `apps/ios/fastlane/.env.example` and `apps/android/fastlane/.env.example` reference exactly
those local credential files. Nothing is currently committed — this is preventive.

**Fix:** add `*.pem`, `*.key`, `*.p8`, `*.p12`, `*.pfx`, `*-service-account.json`,
`AuthKey_*.json` to root `.gitignore`.

## 7. `workflow_dispatch` inputs interpolated into shell / runner label (CI hardening) — Low · `hardening`

**Location:** `.github/workflows/package-acceptance.yml:667` (`advisory="${{ inputs.advisory }}"`), `.github/workflows/crabbox-hydrate.yml:45,338,571` (`runs-on: [self-hosted, "${{ inputs.crabbox_runner_label }}"]`)

Trusted `workflow_dispatch`/`workflow_call` inputs are interpolated directly into a `run:`
shell line and into a self-hosted runner label. Only write-access users can trigger these, so
they are not attacker-reachable — but they are the standard hardening pattern to close.

**Fix:** route `advisory` through `env:` and reference `"$ADVISORY"`; constrain
`crabbox_runner_label` with a `type: choice` enum of allowed labels.

---

## Informational (no change required)

- **Divergent SSRF egress path** — `src/media/store.ts:250` legacy `downloadToFile` relies on
  `resolvePinnedHostname` while newer paths use `fetchWithSsrFGuard`. Functionally equivalent
  today; consolidating on one guard reduces future drift.
- **`patches/@openclaw__fs-safe@0.4.1.patch`** relaxes `fsync` to best-effort (swallows `EPERM`).
  Durability-only, not a security control; legitimate compatibility change.

## Method

Audit fanned out across four domains (CI/CD workflows, shell/Docker/deploy, `src/**` runtime
security, supply-chain/config). Every reported finding was verified against the actual source;
data-flow-traced classes (SSRF, path traversal, command exec, secret handling, prototype
pollution) reached only guarded sinks and produced no confirmed exploit.
