#!/usr/bin/env node
/**
 * KeepIt Security Scanner & Git Hook Guard (scripts/security-scan.js)
 *
 * Enforces pre-commit, pre-push, and repository-wide secret & policy checks:
 * 1. Prevents staging/tracking of .env files, private keys, certificates, SQL dumps, or backups.
 * 2. Scans file contents / diffs for secrets (SMTP/Gmail app passwords, Supabase service-role keys,
 *    private keys, cloud/API tokens, database connection strings, hardcoded credentials).
 * 3. Never prints actual secret values in logs or terminal output (prints only file path, line,
 *    rule ID, secret category, and safe remediation steps).
 * 4. Invokes `gitleaks` binary with `--redact` if installed locally.
 * 5. Validates remote and branch destination during `pre-push`.
 */

const fs = require('fs');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');

const ROOT_DIR = path.resolve(__dirname, '..');
const args = process.argv.slice(2);
const mode = args.includes('--staged')
  ? 'staged'
  : args.includes('--pre-push')
  ? 'pre-push'
  : 'all';

// Prohibited file path patterns (must never be committed or tracked)
const PROHIBITED_FILE_PATTERNS = [
  { regex: /(?:^|\/)\.env(?:\..+)?$/, allow: /(?:^|\/)\.env\.(?:example|template)$/, category: 'Environment / Secret Configuration (.env)' },
  { regex: /^(?:server\.js|send_otp\.js|send_otp\.py|api\/.*)$/i, category: 'Private Backend / Server Script (Excluded from GitHub)' },
  { regex: /^(?:reference\/.*|refrence.*\.(?:jpg|png))$/i, category: 'Local Reference Screenshot (Excluded from GitHub)' },
  { regex: /\.(?:pem|key|p12|pfx|keystore|jks)$/i, category: 'Private Key / Certificate File' },
  { regex: /(?:^|\/)(?:id_rsa|id_ed25519|credentials\.json|service-account[^/]*\.json)$/i, category: 'Private SSH / Cloud Service Account Credential' },
  { regex: /(?:^|\/)\.(?:aws|azure|gcloud|vercel)\//i, category: 'Cloud / Deployment Credential Directory' },
  { regex: /\.(?:sql|dump|bak|backup)$/i, category: 'Database Dump / Backup File' },
  { regex: /\.backup\.html$/i, category: 'Local Backup HTML File' },
  { regex: /(?:^|\/)(?:backups|database-dumps|logs)\//i, category: 'Backup / Log Directory' },
  { regex: /\.log$/i, category: 'Application / Debug Log File' }
];

// Safe placeholder tokens allowed in templates/examples
const SAFE_PLACEHOLDERS = new Set([
  'your-email@gmail.com',
  'your-16-char-google-app-password',
  'your-16-char-app-password',
  'your-supabase-publishable-or-anon-key',
  'your-supabase-service-role-key',
  'https://your-project-id.supabase.co',
  'https://your-project.supabase.co',
  'placeholder',
  'changeme',
  'example'
]);

// Secret content detection rules (never output matched value)
const SECRET_RULES = [
  {
    id: 'PRIVATE_KEY_BLOCK',
    category: 'Cryptographic Private Key',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
    remediation: 'Remove the private key from source control immediately, store it outside the repository, and rotate the key pair.'
  },
  {
    id: 'SUPABASE_SECRET_KEY',
    category: 'Supabase Secret / Service-Role Key',
    regex: /\bsb_secret_[A-Za-z0-9_-]{16,}\b/,
    remediation: 'Never commit sb_secret_ or service_role keys. Move the key to .env (server-only) and rotate it in Supabase Dashboard -> Settings -> API.'
  },
  {
    id: 'SUPABASE_SERVICE_ROLE_ASSIGNMENT',
    category: 'Supabase Service-Role Key Assignment',
    regex: /SUPABASE_SERVICE_ROLE_KEY\s*[:=]\s*['"]([A-Za-z0-9._-]{20,})['"]/i,
    group: 1,
    remediation: 'Remove hardcoded SUPABASE_SERVICE_ROLE_KEY from code. Read it strictly from process.env.SUPABASE_SERVICE_ROLE_KEY.'
  },
  {
    id: 'GMAIL_APP_PASSWORD_ASSIGNMENT',
    category: 'Gmail / SMTP App Password',
    regex: /(?:GMAIL_APP_PASSWORD|gmailPass|smtp_pass|app_password)\s*(?:[:=]|\|\|)\s*['"]([a-z]{4}\s?[a-z]{4}\s?[a-z]{4}\s?[a-z]{4})['"]/i,
    group: 1,
    remediation: 'Remove the hardcoded 16-character Google App Password. Store it in local .env (GMAIL_APP_PASSWORD) and revoke/regenerate it in Google Account Security.'
  },
  {
    id: 'HARDCODED_JWT_FALLBACK',
    category: 'Hardcoded JWT / API Token Fallback',
    regex: /SUPABASE_(?:ANON_|SERVICE_ROLE_)?KEY\s*.*['"](eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,})['"]/,
    group: 1,
    remediation: 'Move the JWT token into .env (SUPABASE_ANON_KEY or SUPABASE_SERVICE_ROLE_KEY) instead of hardcoding it in backend scripts.'
  },
  {
    id: 'DATABASE_CONNECTION_STRING',
    category: 'Database Connection URI with Credentials',
    regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/([^:\s'"]+):([^@\s'"]+)@[^\s'"]+/i,
    group: 2,
    remediation: 'Move the database connection URI to DATABASE_URL in .env and rotate the database password.'
  },
  {
    id: 'GITHUB_ACCESS_TOKEN',
    category: 'GitHub Personal Access / Fine-Grained Token',
    regex: /\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}|gho_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36})\b/,
    remediation: 'Remove the GitHub token from code and revoke it immediately in GitHub Settings -> Developer settings -> Personal access tokens.'
  },
  {
    id: 'AWS_ACCESS_KEY_ID',
    category: 'AWS Access Key ID',
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
    remediation: 'Remove the AWS Access Key ID and deactivate/rotate the key in AWS IAM.'
  },
  {
    id: 'AI_PROVIDER_API_KEY',
    category: 'AI / Cloud Provider Secret Key',
    regex: /\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{32,}|AIza[0-9A-Za-z_-]{35})\b/,
    remediation: 'Remove the API key from tracked files, store it in .env, and rotate it in the provider console.'
  }
];

function git(cmdArgs) {
  try {
    return execFileSync('git', cmdArgs, { cwd: ROOT_DIR, encoding: 'utf8' }).trim();
  } catch (_) {
    return '';
  }
}

function isProhibitedFile(relPath) {
  const normalized = relPath.replace(/\\/g, '/');
  for (const rule of PROHIBITED_FILE_PATTERNS) {
    if (rule.regex.test(normalized)) {
      if (rule.allow && rule.allow.test(normalized)) continue;
      return rule.category;
    }
  }
  return null;
}

function getFilesToCheck() {
  if (mode === 'staged') {
    const out = git(['diff', '--cached', '--name-only', '--diff-filter=ACMR']);
    return out ? out.split(/\r?\n/).filter(Boolean) : [];
  }
  const tracked = git(['ls-files']);
  return tracked ? tracked.split(/\r?\n/).filter(Boolean) : [];
}

function scanFileContent(relPath, content, findings) {
  if (relPath === 'scripts/security-scan.js' || relPath === '.gitleaks.toml') {
    return;
  }
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.includes('gitleaks:allow') || line.includes('security-scan:allow')) {
      continue;
    }
    for (const rule of SECRET_RULES) {
      const m = line.match(rule.regex);
      if (m) {
        const candidate = (rule.group && m[rule.group] ? m[rule.group] : m[0]).trim();
        if (SAFE_PLACEHOLDERS.has(candidate.toLowerCase())) continue;
        if (relPath === '.env.example' || relPath === '.env.template') {
          if (candidate.startsWith('your-') || candidate.includes('example')) continue;
        }
        findings.push({
          type: 'SECRET_DETECTED',
          file: relPath,
          line: i + 1,
          ruleId: rule.id,
          category: rule.category,
          remediation: rule.remediation
        });
      }
    }
  }
}

function runGitleaksIfInstalled() {
  const which = spawnSync('which', ['gitleaks'], { encoding: 'utf8' });
  if (which.status !== 0) {
    return { installed: false, ok: true };
  }
  const gitleaksArgs =
    mode === 'staged'
      ? ['protect', '--staged', '--redact', '--config', '.gitleaks.toml', '--no-banner']
      : ['detect', '--source', '.', '--no-git', '--redact', '--config', '.gitleaks.toml', '--no-banner'];

  const res = spawnSync('gitleaks', gitleaksArgs, { cwd: ROOT_DIR, encoding: 'utf8' });
  return {
    installed: true,
    ok: res.status === 0
  };
}

function validatePrePush() {
  const remoteName = process.env.GIT_PUSH_REMOTE || args[1] || 'origin';
  const remoteUrl = process.env.GIT_PUSH_URL || args[2] || git(['remote', 'get-url', remoteName]);
  const branch = git(['rev-parse', '--abbrev-ref', 'HEAD']);

  const issues = [];
  if (!remoteUrl) {
    issues.push({
      type: 'REMOTE_CONFIG',
      file: '(git remote)',
      line: 0,
      ruleId: 'MISSING_REMOTE_URL',
      category: 'Unverified Git Remote Destination',
      remediation: 'Verify your git remote URL with `git remote -v` before pushing.'
    });
  }
  return { remoteName, remoteUrl, branch, issues };
}

function main() {
  const findings = [];

  // 1. Verify .env is not tracked by Git
  const trackedEnv = git(['ls-files', '.env', '.env.*'])
    .split(/\r?\n/)
    .filter(f => f && f !== '.env.example' && f !== '.env.template');

  for (const envFile of trackedEnv) {
    findings.push({
      type: 'PROHIBITED_TRACKED_FILE',
      file: envFile,
      line: 0,
      ruleId: 'TRACKED_ENV_FILE',
      category: 'Tracked Environment File (.env)',
      remediation: `Remove from Git index without deleting local file: git rm --cached "${envFile}"`
    });
  }

  // 2. Inspect target files for prohibited paths and secret contents
  const files = getFilesToCheck();
  for (const relPath of files) {
    const prohibitedCategory = isProhibitedFile(relPath);
    if (prohibitedCategory) {
      findings.push({
        type: 'PROHIBITED_FILE',
        file: relPath,
        line: 0,
        ruleId: 'PROHIBITED_FILE_PATH',
        category: prohibitedCategory,
        remediation: `Unstage or untrack this file with: git rm --cached "${relPath}" and ensure it matches .gitignore.`
      });
      continue;
    }

    const fullPath = path.join(ROOT_DIR, relPath);
    if (!fs.existsSync(fullPath) || fs.statSync(fullPath).isDirectory()) continue;

    let content = '';
    if (mode === 'staged') {
      try {
        content = execFileSync('git', ['show', `:${relPath}`], {
          cwd: ROOT_DIR,
          encoding: 'utf8',
          maxBuffer: 25 * 1024 * 1024
        });
      } catch (_) {
        content = fs.readFileSync(fullPath, 'utf8');
      }
    } else {
      content = fs.readFileSync(fullPath, 'utf8');
    }

    scanFileContent(relPath, content, findings);
  }

  // 3. Pre-push destination verification
  if (mode === 'pre-push') {
    const pushInfo = validatePrePush();
    findings.push(...pushInfo.issues);
  }

  // 4. Optional local Gitleaks binary check (with --redact)
  const gitleaksRes = runGitleaksIfInstalled();
  if (gitleaksRes.installed && !gitleaksRes.ok) {
    findings.push({
      type: 'GITLEAKS_ALERT',
      file: '(repository)',
      line: 0,
      ruleId: 'GITLEAKS_RULE_MATCH',
      category: 'Gitleaks Secret Scanner Match',
      remediation: 'Run `gitleaks protect --staged --redact` to review redacted findings and move secrets to .env.'
    });
  }

  // 5. Report results safely (NEVER printing secret values)
  if (findings.length > 0) {
    console.error('\n========================================================================');
    console.error('🚨 SECURITY CHECK FAILED — OPERATION BLOCKED TO PROTECT REPOSITORY 🚨');
    console.error('========================================================================');
    console.error(`Scan Mode : ${mode.toUpperCase()}`);
    console.error(`Violations: ${findings.length} security issue(s) detected (secret values redacted)\n`);

    findings.forEach((f, idx) => {
      const loc = f.line > 0 ? `${f.file}:${f.line}` : f.file;
      console.error(`  [${idx + 1}] ${f.category} (${f.ruleId})`);
      console.error(`      Location   : ${loc}`);
      console.error(`      Remediation: ${f.remediation}\n`);
    });

    console.error('------------------------------------------------------------------------');
    console.error('How to resolve:');
    console.error('  1. Move real credentials into your untracked local `.env` file.');
    console.error('  2. Unstage prohibited files: `git restore --staged <file>` or `git rm --cached <file>`.');
    console.error('  3. If a finding is a verified false positive, see `SECURITY.md` for allowlist review.');
    console.error('========================================================================\n');
    process.exit(1);
  }

  console.log(`✅ [KeepIt Security Scan: ${mode.toUpperCase()}] Passed (${files.length} file(s) verified, 0 secrets or prohibited files exposed).`);
  process.exit(0);
}

main();
