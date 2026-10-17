# Security & Secret Protection Policy

This document describes the DevSecOps controls configured in the **KeepIt Habit Tracker** repository to prevent secrets, credentials, sensitive configuration, private keys, and prohibited files from being committed or pushed to GitHub.

---

## 1. Environment Configuration & Secret Storage

1. **Local Secrets (`.env`):**
   - Keep all real credentials (`GMAIL_USER`, `GMAIL_APP_PASSWORD`, `SUPABASE_SERVICE_ROLE_KEY`, etc.) exclusively in your local `.env` file.
   - `.env` and `.env.*` are strictly ignored by `.gitignore` and verified by `scripts/security-scan.js`.
2. **Template File (`.env.example`):**
   - Only variable names and safe placeholder strings belong in `.env.example`.
   - Never place real API keys, Google App Passwords, database passwords, or JWT tokens in `.env.example`.
3. **Production Secrets:**
   - Store production secrets in your hosting provider's secret manager (e.g., Vercel Environment Variables, GitHub Actions Secrets, Supabase Vault).
4. **Frontend vs. Backend Boundary:**
   - Browser-facing code (`index.html`) may only reference public project URLs and Supabase publishable/anon keys (`sb_publishable_...`) protected by Row-Level Security (RLS).
   - Privileged credentials (`GMAIL_APP_PASSWORD`, `SUPABASE_SERVICE_ROLE_KEY`, `sb_secret_...`) must remain strictly in server-side code (`server.js`, `api/send-otp.js`, `send_otp.js`, `send_otp.py`) loaded from environment variables.

---

## 2. Automated Secret Scanning & Git Hooks

Three layers of automated scanning protect this repository:

| Layer | Trigger | Mechanism |
| :--- | :--- | :--- |
| **Pre-Commit Hook** | `git commit` | `.githooks/pre-commit` runs `node scripts/security-scan.js --staged` (plus `gitleaks protect --staged --redact` if installed) |
| **Pre-Push Hook** | `git push` | `.githooks/pre-push` runs `node scripts/security-scan.js --pre-push` to scan all tracked files and verify the remote destination |
| **GitHub Actions CI** | `push` / `pull_request` | `.github/workflows/security-scan.yml` runs `node scripts/security-scan.js --all` and `gitleaks/gitleaks-action@v2` |

### Manual Commands
```bash
# Scan all tracked files in the repository
npm run security:scan

# Scan currently staged changes before committing
npm run security:staged

# Re-install / ensure Git hooks are active
npm run prepare
```

---

## 3. Handling False Positives Safely

If a legitimate non-secret line triggers a rule:

1. **Verify first** that the value is genuinely a dummy placeholder, public identifier, or test fixture—never allowlist a real credential.
2. **Line-level allowlist comment:** Append `// gitleaks:allow` or `// security-scan:allow` (or `# gitleaks:allow` in Python/YAML) to that specific line.
3. **Configuration allowlist:** For recurring safe patterns or template files, add a narrow regex or path exception under `[allowlist]` in `.gitleaks.toml` and `SAFE_PLACEHOLDERS` in `scripts/security-scan.js`.
4. **Peer review:** All changes to `.gitleaks.toml`, `.gitignore`, or `scripts/security-scan.js` must be reviewed in Pull Requests.

---

## 4. Emergency Bypass Policy (Restricted)

Normal developer workflows **must never** bypass pre-commit or pre-push checks.

In a verified production incident where a false positive blocks an urgent hotfix and cannot be immediately allowlisted:
1. Confirm with `npm run security:staged` that zero real secrets or `.env` files are staged.
2. Document the reason in the commit/PR description.
3. Understand that **GitHub Actions (`security-scan.yml`) and GitHub Push Protection will still scan the push on the server**—bypassing a local hook (`--no-verify`) does not bypass CI enforcement.

---

## 5. Remediating Tracked Files & Historical Secret Exposure

- **Removing an accidentally tracked sensitive file without deleting it locally:**
  ```bash
  git rm --cached <path-to-sensitive-file>
  ```
- **Why deleting a secret in a new commit is not enough:**
  Git preserves the full snapshot of every previous commit. Removing a hardcoded credential in a new commit prevents future exposure in `HEAD`, but the secret remains readable in earlier commits (`git log -p`).
- **Mandatory action when a secret is exposed in Git history:**
  1. **Immediately revoke and rotate the credential** in the provider's console (e.g., Google Account -> Security -> App Passwords, or Supabase Dashboard -> API Settings). Once revoked, the historical string is permanently unusable.
  2. Only purge shared Git history (`git filter-repo` / BFG Repo-Cleaner) with explicit authorization from the repository owner, as it rewrites commit SHAs across branches.
