const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const ignoredDirectories = new Set(['.git', 'node_modules', 'coverage']);
const findings = [];

const rules = [
  ['private-key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g],
  ['github-token', /(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/g],
  ['openai-style-key', /sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}/g],
  ['aws-access-key', /AKIA[A-Z0-9]{16}/g],
  ['google-api-key', /AIza[A-Za-z0-9_-]{30,}/g],
  ['slack-token', /xox[baprs]-[A-Za-z0-9-]{20,}/g],
  ['stripe-live-key', /[sr]k_live_[A-Za-z0-9]{16,}/g],
  ['jwt', /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g],
  ['sensitive-assignment', /(?:api[_-]?key|secret|token|password|passwd|pwd)\s*["']?\s*[:=]\s*["']?([A-Za-z0-9+/_=.-]{20,})/gi],
];

function walk(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue;
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) walk(absolute);
    else if (entry.isFile()) scanFile(absolute);
  }
}

function scanFile(file) {
  const buffer = fs.readFileSync(file);
  if (buffer.includes(0)) return;
  const content = buffer.toString('utf8');
  const lines = content.split(/\r?\n/);

  for (const [ruleName, rule] of rules) {
    rule.lastIndex = 0;
    let match;
    while ((match = rule.exec(content)) !== null) {
      const lineNumber = content.slice(0, match.index).split(/\r?\n/).length;
      const line = lines[lineNumber - 1].toLowerCase();
      if (/synthetic|example|demo|redacted/.test(line)) continue;
      findings.push(`${ruleName} at ${path.relative(root, file)}:${lineNumber}`);
    }
  }
}

walk(root);

if (findings.length > 0) {
  console.error(`Secret scan failed with ${findings.length} finding(s):`);
  for (const finding of findings) console.error(`- ${finding}`);
  process.exitCode = 1;
} else {
  console.log('Secret scan passed: 0 findings.');
}
