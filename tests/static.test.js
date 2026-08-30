const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');

test('the page has no external font or network dependency', () => {
  const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
  const app = fs.readFileSync(path.join(root, 'app.js'), 'utf8');

  assert.doesNotMatch(html, /fonts\.(?:googleapis|gstatic)\.com/i);
  assert.doesNotMatch(html, /sk-(?:proj-)?[A-Za-z0-9_-]{10,}/);
  assert.match(html, /connect-src 'none'/);
  assert.doesNotMatch(app, /\b(?:fetch|XMLHttpRequest|WebSocket|sendBeacon)\b/);
});

test('private source artifacts are absent from the candidate', () => {
  const forbidden = [
    'AI修改版本',
    '工具生成脱敏版本',
    '.DS_Store',
  ];

  for (const name of forbidden) {
    assert.equal(fs.existsSync(path.join(root, name)), false, `${name} must not be committed`);
  }
});

test('the UI never overstates best-effort redaction as safe', () => {
  const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
  const app = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
  const userFacingText = `${html}\n${app}`;

  assert.doesNotMatch(userFacingText, /可以放心|可以安全复制/);
  assert.match(userFacingText, /人工复核/);
});
