const test = require('node:test');
const assert = require('node:assert/strict');

const engine = require('../app.js');

function assertRoundTrip(input) {
  const redacted = engine.redactContent(input);
  const restored = engine.restoreContent(redacted.result);
  assert.equal(restored.result, input);
  return redacted;
}

test('JSON redacts a sensitive field without substring false positives', () => {
  const input = '{"api_key":"json-demo-value","keyboard":"compact","monkey":"banana"}';
  const redacted = assertRoundTrip(input);

  assert.equal(redacted.redactedCount, 1);
  assert.match(redacted.result, /"api_key":"\{\{REDACTED_1\}\}"/);
  assert.match(redacted.result, /"keyboard":"compact"/);
  assert.match(redacted.result, /"monkey":"banana"/);
});

test('YAML redacts short sensitive values and leaves ordinary fields alone', () => {
  const input = 'password: xy\nhockey_team: bears\nauthorship: rice';
  const redacted = assertRoundTrip(input);

  assert.equal(redacted.redactedCount, 1);
  assert.match(redacted.result, /^password: \{\{REDACTED_1\}\}$/m);
  assert.match(redacted.result, /^hockey_team: bears$/m);
  assert.match(redacted.result, /^authorship: rice$/m);
});

for (const [format, input] of [
  ['ENV', 'API_TOKEN="env-synthetic-value"'],
  ['TOML', 'client_secret = "toml-synthetic-value"'],
]) {
  test(`${format} double-quoted values are redacted exactly once`, () => {
    const redacted = assertRoundTrip(input);
    const mapping = engine.getMappingSnapshot();

    assert.equal(redacted.redactedCount, 1);
    assert.equal(mapping.counter, 1);
    assert.equal(Object.keys(mapping.placeholderToValue).length, 1);
    assert.doesNotMatch(mapping.placeholderToValue['{{REDACTED_1}}'], /REDACTED/);
  });
}

test('a known bare prefix is found after the first line', () => {
  const syntheticToken = 'sk-' + 'syntheticvalue123456789';
  const input = `ordinary first line\n${syntheticToken}`;
  const redacted = assertRoundTrip(input);

  assert.equal(redacted.redactedCount, 1);
  assert.doesNotMatch(redacted.result, /syntheticvalue/);
});

test('sensitive URL query values are redacted without replacing the URL', () => {
  const input = 'callback=https://example.invalid/cb?token=url-synthetic-value&mode=test';
  const redacted = assertRoundTrip(input);

  assert.equal(redacted.redactedCount, 1);
  assert.match(redacted.result, /^callback=https:\/\/example\.invalid\/cb\?token=\{\{REDACTED_1\}\}&mode=test$/);
});

test('restore handles exact and generic placeholders in the same document', () => {
  const input = [
    '{',
    '  "api_key": "alpha-synthetic-value",',
    '  "password": "bravo-synthetic-value"',
    '}',
  ].join('\n');
  const redacted = engine.redactContent(input);
  const mixed = redacted.result.replace('{{REDACTED_2}}', '***REDACTED***');
  const restored = engine.restoreContent(mixed);

  assert.equal(restored.result, input);
  assert.equal(restored.restoredCount, 2);
  assert.deepEqual(restored.unresolved, []);
});

test('an unknown exact placeholder is not confused with a generic mask', () => {
  engine.redactContent('password=bravo-synthetic-value');
  const restored = engine.restoreContent('password=***REDACTED***\nother={{REDACTED_999}}');

  assert.equal(restored.result, 'password=bravo-synthetic-value\nother={{REDACTED_999}}');
  assert.deepEqual(restored.unresolved, ['{{REDACTED_999}}']);
});
