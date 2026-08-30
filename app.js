/**
 * TranslateNoKey — 配置文件敏感信息脱敏/还原引擎
 * 所有数据仅在本地浏览器处理，不会上传到任何服务器
 */

(function () {
  'use strict';

  // ==================== Redaction Engine ====================

  // 敏感字段名模式（不区分大小写）
  const SENSITIVE_FIELD_PATTERNS = [
    'key', 'secret', 'token', 'password', 'passwd', 'pwd',
    'credential', 'auth', 'api_key', 'apikey', 'api-key',
    'access_key', 'access_token', 'private_key', 'client_secret',
    'bearer', 'authorization', 'signing', 'encryption',
    'passphrase', 'salt', 'hash', 'hmac',
    'webhook', 'endpoint_secret',
    'connection_string', 'database_url', 'db_url', 'db_password',
    'smtp_password', 'mail_password',
    'aws_secret', 'aws_access', 'gcp_key', 'azure_key',
    'openai', 'anthropic', 'cohere', 'replicate',
    'stripe', 'twilio', 'sendgrid', 'mailgun',
    'github_token', 'gitlab_token', 'npm_token',
    'sentry_dsn', 'dsn',
  ];

  const SENSITIVE_FIELD_NAMES = new Set(SENSITIVE_FIELD_PATTERNS.map(normalizeFieldName));

  // 已知的敏感值前缀模式
  const SENSITIVE_VALUE_PREFIXES = [
    /^sk-[a-zA-Z0-9_-]{10,}/,           // OpenAI
    /^pk-[a-zA-Z0-9_-]{10,}/,           // Public keys
    /^sk_live_[a-zA-Z0-9_-]{10,}/,      // Stripe live
    /^sk_test_[a-zA-Z0-9_-]{10,}/,      // Stripe test
    /^pk_live_[a-zA-Z0-9_-]{10,}/,      // Stripe public
    /^pk_test_[a-zA-Z0-9_-]{10,}/,      // Stripe public test
    /^ghp_[a-zA-Z0-9]{10,}/,            // GitHub PAT
    /^gho_[a-zA-Z0-9]{10,}/,            // GitHub OAuth
    /^ghs_[a-zA-Z0-9]{10,}/,            // GitHub App
    /^github_pat_[a-zA-Z0-9_]{10,}/,    // GitHub fine-grained PAT
    /^xoxb-[a-zA-Z0-9-]{10,}/,          // Slack bot
    /^xoxp-[a-zA-Z0-9-]{10,}/,          // Slack user
    /^xapp-[a-zA-Z0-9-]{10,}/,          // Slack app
    /^AKIA[A-Z0-9]{12,}/,              // AWS Access Key ID
    /^AIza[a-zA-Z0-9_-]{30,}/,          // Google API Key
    /^ya29\.[a-zA-Z0-9_-]{10,}/,        // Google OAuth token
    /^eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}/,  // JWT
    /^bearer\s+\S{10,}/i,               // Bearer token
    /^Basic\s+[a-zA-Z0-9+/=]{10,}/,     // Basic auth
    /^npm_[a-zA-Z0-9]{10,}/,            // npm token
    /^snyk_[a-zA-Z0-9]{10,}/,           // Snyk token
    /^SG\.[a-zA-Z0-9_-]{10,}/,          // SendGrid
    /^key-[a-zA-Z0-9]{10,}/,            // Generic key
    /^sec-[a-zA-Z0-9]{10,}/,            // Generic secret
    /^whsec_[a-zA-Z0-9]{10,}/,          // Webhook secret
    /^AC[a-f0-9]{32}/,                  // Twilio Account SID
    /^sk-ant-[a-zA-Z0-9_-]{10,}/,       // Anthropic
    /^r8_[a-zA-Z0-9]{10,}/,             // Replicate
  ];

  // 非敏感值的排除模式
  const NON_SENSITIVE_PATTERNS = [
    /^https?:\/\//i,                               // URLs (alone)
    /^v?\d+\.\d+/,                                 // Version numbers
    /^(true|false|null|none|yes|no|on|off)$/i,     // Boolean-like
    /^\d{1,5}$/,                                    // Small numbers (ports etc)
    /^(localhost|127\.0\.0\.1|0\.0\.0\.0)$/,       // Localhost
    /^[a-z]{1,15}$/,                                // Short lowercase words
    /^\*+$/,                                        // Already masked
    /^\/[a-zA-Z0-9/._-]+$/,                        // File paths
    /^\$\{/,                                       // Variable references
    /^%/,                                           // Variable references
    /^(development|production|staging|test|debug|info|warn|error)$/i, // Env names
    /^(utf-?8|ascii|latin1|iso-8859-1)$/i,         // Encodings
    /^(json|xml|html|text|csv|yaml|toml)$/i,       // Format names
    /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$/i,  // HTTP methods
    /^[a-z0-9]+(-[a-z0-9]+)*\.[a-z]{2,10}$/i,     // Domain-like (simple)
  ];

  /**
   * 判断一个值是否看起来像敏感数据
   */
  function looksLikeSensitiveValue(value) {
    const trimmed = value.trim();
    if (trimmed.length < 8) return false;

    // 检查已知前缀
    for (const prefix of SENSITIVE_VALUE_PREFIXES) {
      if (prefix.test(trimmed)) return true;
    }

    // 排除已知非敏感模式
    for (const pattern of NON_SENSITIVE_PATTERNS) {
      if (pattern.test(trimmed)) return false;
    }

    // 高熵长字符串（≥32 字符，主要由字母数字组成）
    if (trimmed.length >= 32) {
      const alphanumCount = (trimmed.match(/[a-zA-Z0-9]/g) || []).length;
      if (alphanumCount / trimmed.length > 0.7) return true;
    }

    return false;
  }

  /**
   * 判断字段名是否匹配敏感模式
   */
  function isSensitiveFieldName(fieldName) {
    const normalized = normalizeFieldName(fieldName);
    if (!normalized) return false;

    const padded = `_${normalized}_`;
    for (const pattern of SENSITIVE_FIELD_NAMES) {
      if (normalized === pattern || padded.includes(`_${pattern}_`)) return true;
    }
    return false;
  }

  function normalizeFieldName(fieldName) {
    return String(fieldName)
      .replace(/['"]/g, '')
      .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '_')
      .replace(/^_+|_+$/g, '');
  }

  function isAlreadyRedactedValue(value) {
    const trimmed = value.trim();
    if (/^\{\{REDACTED_\d+\}\}$/.test(trimmed)) return true;
    return GENERIC_REDACTED_PATTERNS.includes(trimmed);
  }

  // ==================== Mapping Store ====================

  let mappingStore = {
    counter: 0,
    placeholderToValue: {},   // {{REDACTED_N}} -> original value
    valueToPlaceholder: {},   // original value -> {{REDACTED_N}}
    placeholderToField: {},   // {{REDACTED_N}} -> field name (for display)
    orderedRedactions: [],    // [{fieldName, placeholder, originalValue}, ...] in order
  };

  function resetMapping() {
    mappingStore = {
      counter: 0,
      placeholderToValue: {},
      valueToPlaceholder: {},
      placeholderToField: {},
      orderedRedactions: [],
    };
  }

  function getOrCreatePlaceholder(value, fieldName) {
    if (mappingStore.valueToPlaceholder[value]) {
      return mappingStore.valueToPlaceholder[value];
    }
    mappingStore.counter++;
    const placeholder = `{{REDACTED_${mappingStore.counter}}}`;
    mappingStore.placeholderToValue[placeholder] = value;
    mappingStore.valueToPlaceholder[value] = placeholder;
    mappingStore.placeholderToField[placeholder] = fieldName || '(auto-detected)';
    mappingStore.orderedRedactions.push({ fieldName: fieldName || '', placeholder, originalValue: value });
    return placeholder;
  }

  // AI 可能使用的通用脱敏替代模式
  const GENERIC_REDACTED_PATTERNS = [
    '***REDACTED***',
    '**REDACTED**',
    '*REDACTED*',
    '[REDACTED]',
    '<REDACTED>',
    'REDACTED',
    '***REMOVED***',
    '[REMOVED]',
    '***HIDDEN***',
    '[HIDDEN]',
    '***SENSITIVE***',
    '[SENSITIVE]',
    '***API_KEY***',
    '***SECRET***',
    '***TOKEN***',
    'YOUR_API_KEY_HERE',
    'YOUR_SECRET_HERE',
    'YOUR_TOKEN_HERE',
    '<your-api-key>',
    '<your-secret>',
    '<your-token>',
  ];

  /**
   * 从一行文本中提取字段名（JSON/YAML/TOML/ENV 格式）
   */
  function extractFieldNameFromLine(line) {
    // JSON: "fieldName": "value"
    let m = line.match(/"([^"]+)"\s*:/);
    if (m) return m[1];
    // YAML: fieldName: value
    m = line.match(/^\s*([\w][\w.-]*)\s*:/);
    if (m) return m[1];
    // ENV/TOML: FIELD_NAME = value  or  FIELD_NAME=value
    m = line.match(/^\s*([\w][\w.-]*)\s*=/);
    if (m) return m[1];
    return null;
  }

  // ==================== Redaction Logic ====================

  /**
   * 主脱敏函数
   */
  function redactContent(input) {
    resetMapping();
    let result = input;
    let redactedCount = 0;

    // 1. JSON 格式: "key": "value"
    result = result.replace(
      /("(?:[^"\\]|\\.)*")(\s*:\s*)("(?:[^"\\]|\\.)*")/g,
      (match, keyPart, separator, valuePart) => {
        const key = keyPart.slice(1, -1);
        const value = valuePart.slice(1, -1);
        if (!value || isAlreadyRedactedValue(value)) return match;
        if (isSensitiveFieldName(key) || looksLikeSensitiveValue(value)) {
          const placeholder = getOrCreatePlaceholder(value, key);
          redactedCount++;
          return `${keyPart}${separator}"${placeholder}"`;
        }
        return match;
      }
    );

    // 2. YAML 格式: key: value (unquoted or quoted)
    result = result.replace(
      /^([ \t]*)([\w][\w.-]*)\s*:\s*(?:"([^"]*(?:\\.[^"]*)*)"|'([^']*)'|([^\n\r#][^\n\r]*))\s*$/gm,
      (match, indent, key, dqVal, sqVal, plainVal) => {
        const value = dqVal !== undefined ? dqVal : (sqVal !== undefined ? sqVal : (plainVal || '').trim());
        if (/^\s*$/.test(value) || isAlreadyRedactedValue(value)) return match;
        // skip if value looks like a sub-mapping or list
        if (/^[\[{]/.test(value)) return match;

        if (isSensitiveFieldName(key) || looksLikeSensitiveValue(value)) {
          const placeholder = getOrCreatePlaceholder(value, key);
          redactedCount++;
          if (dqVal !== undefined) return `${indent}${key}: "${placeholder}"`;
          if (sqVal !== undefined) return `${indent}${key}: '${placeholder}'`;
          return `${indent}${key}: ${placeholder}`;
        }
        return match;
      }
    );

    // 3. ENV/TOML 格式: KEY=value 或 key = "value"
    result = result.replace(
      /^([ \t]*)([\w][\w.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\n\r]*))\s*$/gm,
      (match, indent, key, dqVal, sqVal, plainVal) => {
        const value = dqVal !== undefined ? dqVal : (sqVal !== undefined ? sqVal : (plainVal || '').trim());
        if (/^\s*$/.test(value) || isAlreadyRedactedValue(value)) return match;

        if (isSensitiveFieldName(key) || looksLikeSensitiveValue(value)) {
          const placeholder = getOrCreatePlaceholder(value, key);
          redactedCount++;
          const separator = match.slice(indent.length + key.length).match(/^\s*=\s*/)?.[0] || '=';
          if (dqVal !== undefined) return `${indent}${key}${separator}"${placeholder}"`;
          if (sqVal !== undefined) return `${indent}${key}${separator}'${placeholder}'`;
          return `${indent}${key}${separator}${placeholder}`;
        }
        return match;
      }
    );

    // 4. 扫描结构化字段之外的已知敏感前缀，包括非首行文本。
    for (const prefix of SENSITIVE_VALUE_PREFIXES) {
      const source = prefix.source.replace(/^\^/, '');
      const globalPrefix = new RegExp(`(^|[\\s"'=:,(])(${source})(?=$|[\\s"'&),;])`, 'gmi');
      result = result.replace(globalPrefix, (match, boundary, value) => {
        if (isAlreadyRedactedValue(value)) return match;
        if (mappingStore.valueToPlaceholder[value]) {
          return boundary + mappingStore.valueToPlaceholder[value];
        }
        if (!Object.values(mappingStore.placeholderToValue).some(v => value.startsWith(v) || v.startsWith(value))) {
          const placeholder = getOrCreatePlaceholder(value, '(value-pattern)');
          redactedCount++;
          return boundary + placeholder;
        }
        return match;
      });
    }

    // 5. URL 查询参数可能携带 token；只替换敏感参数值，保留 URL 结构。
    result = result.replace(/([?&])([A-Za-z0-9_.-]+)=([^&#\s"'<>]*)/g, (match, separator, key, value) => {
      if (!value || !isSensitiveFieldName(key) || isAlreadyRedactedValue(value)) return match;
      const placeholder = getOrCreatePlaceholder(value, `url:${key}`);
      redactedCount++;
      return `${separator}${key}=${placeholder}`;
    });

    return { result, redactedCount };
  }

  /**
   * 主还原函数 — 支持精确匹配和智能字段名匹配
   *
   * 策略：
   * 1. 先尝试精确匹配 {{REDACTED_N}} 占位符
   * 2. 再扫描 AI 常用的通用脱敏模式（如 ***REDACTED***），
   *    通过字段名 + 出现顺序来匹配对应的原始值
   */
  function restoreContent(input) {
    let result = input;
    let restoredCount = 0;
    const unresolved = [];

    // ---- Pass 1: 精确匹配 {{REDACTED_N}} ----
    const placeholderRegex = /\{\{REDACTED_\d+\}\}/g;
    result = result.replace(placeholderRegex, (ph) => {
      if (mappingStore.placeholderToValue[ph]) {
        restoredCount++;
        return mappingStore.placeholderToValue[ph];
      } else {
        if (!unresolved.includes(ph)) unresolved.push(ph);
        return ph;
      }
    });

    // ---- Pass 2: 智能匹配通用脱敏模式 ----
    // 构建 fieldName -> [originalValues] 的映射（按出现顺序）
    const fieldToValues = {};
    for (const entry of mappingStore.orderedRedactions) {
      const fn = normalizeFieldName(entry.fieldName);
      if (!fieldToValues[fn]) fieldToValues[fn] = [];
      fieldToValues[fn].push(entry.originalValue);
    }

    // 记录每个 fieldName 已消费的索引
    const fieldConsumedIndex = {};

    // 逐行扫描，寻找通用脱敏模式
    const lines = result.split('\n');
    let genericRestoredCount = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // 检查该行是否包含任何通用脱敏模式
      const matchedMask = findGenericMask(line);
      if (!matchedMask) continue;

      // 提取该行的字段名
      const fieldName = extractFieldNameFromLine(line);
      if (!fieldName) continue;

      const fnLower = normalizeFieldName(fieldName);

      // 在映射中查找该字段名
      if (fieldToValues[fnLower] && fieldToValues[fnLower].length > 0) {
        // 获取本字段名的下一个未使用的值
        if (fieldConsumedIndex[fnLower] === undefined) fieldConsumedIndex[fnLower] = 0;
        const idx = fieldConsumedIndex[fnLower];

        if (idx < fieldToValues[fnLower].length) {
          const originalValue = fieldToValues[fnLower][idx];
          fieldConsumedIndex[fnLower] = idx + 1;

          // 替换该行中的通用模式为原始值
          lines[i] = line.slice(0, matchedMask.index) + originalValue + line.slice(matchedMask.index + matchedMask.pattern.length);
          genericRestoredCount++;
        }
      }
    }

    if (genericRestoredCount > 0) {
      result = lines.join('\n');
      restoredCount += genericRestoredCount;
    }

    return { result, restoredCount, unresolved };
  }

  function findGenericMask(line) {
    const exactRanges = Array.from(line.matchAll(/\{\{REDACTED_\d+\}\}/g), match => ({
      start: match.index,
      end: match.index + match[0].length,
    }));

    for (const pattern of GENERIC_REDACTED_PATTERNS) {
      let index = line.indexOf(pattern);
      while (index !== -1) {
        const insideExactPlaceholder = exactRanges.some(range => index >= range.start && index < range.end);
        if (!insideExactPlaceholder) return { pattern, index };
        index = line.indexOf(pattern, index + pattern.length);
      }
    }
    return null;
  }

  const engineApi = {
    redactContent,
    restoreContent,
    resetMapping,
    isSensitiveFieldName,
    getMappingSnapshot: () => JSON.parse(JSON.stringify(mappingStore)),
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = engineApi;
  if (typeof document === 'undefined') return;

  // ==================== UI Logic ====================

  const $ = (id) => document.getElementById(id);

  // Elements
  const originalInput = $('originalInput');
  const redactedOutput = $('redactedOutput');
  const modifiedInput = $('modifiedInput');
  const restoredOutput = $('restoredOutput');

  const redactBtn = $('redactBtn');
  const restoreBtn = $('restoreBtn');
  const copyRedactedBtn = $('copyRedactedBtn');
  const copyRestoredBtn = $('copyRestoredBtn');

  const pasteOriginalBtn = $('pasteOriginalBtn');
  const clearOriginalBtn = $('clearOriginalBtn');
  const pasteModifiedBtn = $('pasteModifiedBtn');
  const clearModifiedBtn = $('clearModifiedBtn');

  const redactedCountEl = $('redactedCount');
  const mappingCountEl = $('mappingCount');
  const restoredCountEl = $('restoredCount');
  const unresolvedCountEl = $('unresolvedCount');
  const unresolvedStat = $('unresolvedStat');
  const restoreStatsBar = $('restoreStatsBar');

  const viewMappingBtn = $('viewMappingBtn');
  const exportMappingBtn = $('exportMappingBtn');
  const importMappingBtn = $('importMappingBtn');
  const clearMappingBtn = $('clearMappingBtn');
  const importFileInput = $('importFileInput');
  const mappingModal = $('mappingModal');
  const closeMappingBtn = $('closeMappingBtn');
  const mappingTableBody = $('mappingTableBody');
  const mappingEmpty = $('mappingEmpty');

  // Toast helper
  function showToast(message, type = 'info') {
    const container = $('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
  }

  // Clipboard helpers
  async function copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Fallback
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.className = 'clipboard-fallback';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      return true;
    }
  }

  async function pasteFromClipboard() {
    try {
      return await navigator.clipboard.readText();
    } catch {
      showToast('无法读取剪贴板，请手动粘贴 (Ctrl/Cmd+V)', 'warning');
      return null;
    }
  }

  // Update mapping table UI
  function updateMappingUI() {
    const entries = Object.entries(mappingStore.placeholderToValue);
    mappingCountEl.textContent = entries.length;

    if (entries.length === 0) {
      mappingTableBody.innerHTML = '';
      mappingEmpty.hidden = false;
      return;
    }

    mappingEmpty.hidden = true;
    mappingTableBody.innerHTML = entries.map(([ph, val]) => {
      const field = mappingStore.placeholderToField[ph] || '-';
      const displayVal = val.length > 60 ? val.slice(0, 30) + '...' + val.slice(-20) : val;
      return `<tr>
        <td class="placeholder-cell">${escapeHtml(ph)}</td>
        <td class="value-cell" title="${escapeHtml(val)}">${escapeHtml(displayVal)}</td>
        <td class="field-cell">${escapeHtml(field)}</td>
      </tr>`;
    }).join('');
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // ---- Event Handlers ----

  // Redact
  redactBtn.addEventListener('click', () => {
    const input = originalInput.value.trim();
    if (!input) {
      showToast('请先粘贴原始配置内容', 'warning');
      return;
    }

    const { result, redactedCount } = redactContent(input);
    redactedOutput.value = result;
    redactedCountEl.textContent = redactedCount;
    copyRedactedBtn.disabled = false;
    updateMappingUI();

    if (redactedCount === 0) {
      showToast('未检测到敏感信息，内容已原样输出', 'info');
    } else {
      showToast(`已脱敏 ${redactedCount} 个敏感值；请人工复核后再复制`, 'success');
    }
  });

  // Restore
  restoreBtn.addEventListener('click', () => {
    const input = modifiedInput.value.trim();
    if (!input) {
      showToast('请先粘贴 AI 修改后的内容', 'warning');
      return;
    }
    if (Object.keys(mappingStore.placeholderToValue).length === 0) {
      showToast('映射表为空，请先执行脱敏或导入映射表', 'error');
      return;
    }

    const { result, restoredCount, unresolved } = restoreContent(input);
    restoredOutput.value = result;
    restoredCountEl.textContent = restoredCount;
    copyRestoredBtn.disabled = false;
    restoreStatsBar.hidden = false;

    if (unresolved.length > 0) {
      unresolvedStat.hidden = false;
      unresolvedCountEl.textContent = unresolved.length;
      showToast(`已还原 ${restoredCount} 个值，${unresolved.length} 个占位符未能匹配`, 'warning');
    } else if (restoredCount > 0) {
      unresolvedStat.hidden = true;
      showToast(`已成功还原 ${restoredCount} 个敏感值`, 'success');
    } else {
      unresolvedStat.hidden = true;
      showToast('未发现占位符，内容已原样输出', 'info');
    }
  });

  // Copy buttons
  copyRedactedBtn.addEventListener('click', async () => {
    await copyToClipboard(redactedOutput.value);
    showToast('脱敏结果已复制到剪贴板', 'success');
  });

  copyRestoredBtn.addEventListener('click', async () => {
    await copyToClipboard(restoredOutput.value);
    showToast('还原结果已复制到剪贴板', 'success');
  });

  // Paste buttons
  pasteOriginalBtn.addEventListener('click', async () => {
    const text = await pasteFromClipboard();
    if (text !== null) {
      originalInput.value = text;
      originalInput.focus();
      showToast('已从剪贴板粘贴', 'info');
    }
  });

  pasteModifiedBtn.addEventListener('click', async () => {
    const text = await pasteFromClipboard();
    if (text !== null) {
      modifiedInput.value = text;
      modifiedInput.focus();
      showToast('已从剪贴板粘贴', 'info');
    }
  });

  // Clear buttons
  clearOriginalBtn.addEventListener('click', () => {
    originalInput.value = '';
    redactedOutput.value = '';
    copyRedactedBtn.disabled = true;
    redactedCountEl.textContent = '0';
    originalInput.focus();
  });

  clearModifiedBtn.addEventListener('click', () => {
    modifiedInput.value = '';
    restoredOutput.value = '';
    copyRestoredBtn.disabled = true;
    restoredCountEl.textContent = '0';
    restoreStatsBar.hidden = true;
    modifiedInput.focus();
  });

  // Mapping modal
  viewMappingBtn.addEventListener('click', () => {
    updateMappingUI();
    mappingModal.classList.add('active');
  });

  closeMappingBtn.addEventListener('click', () => {
    mappingModal.classList.remove('active');
  });

  mappingModal.addEventListener('click', (e) => {
    if (e.target === mappingModal) mappingModal.classList.remove('active');
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && mappingModal.classList.contains('active')) {
      mappingModal.classList.remove('active');
    }
  });

  // Export mapping
  exportMappingBtn.addEventListener('click', () => {
    if (Object.keys(mappingStore.placeholderToValue).length === 0) {
      showToast('映射表为空，无法导出', 'warning');
      return;
    }
    const data = JSON.stringify(mappingStore, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `translate-no-key-mapping-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('映射表已导出', 'success');
  });

  // Import mapping
  importMappingBtn.addEventListener('click', () => {
    importFileInput.click();
  });

  clearMappingBtn.addEventListener('click', () => {
    if (Object.keys(mappingStore.placeholderToValue).length === 0) {
      showToast('映射表已为空', 'info');
      return;
    }
    if (!window.confirm('清空映射后将无法还原当前占位符，且此操作无法撤销。确定继续吗？')) return;

    resetMapping();
    updateMappingUI();
    modifiedInput.value = '';
    restoredOutput.value = '';
    copyRestoredBtn.disabled = true;
    restoreStatsBar.hidden = true;
    showToast('映射表已从当前页面内存中清空', 'success');
  });

  importFileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const data = JSON.parse(event.target.result);
        if (data.placeholderToValue && data.valueToPlaceholder) {
          mappingStore = data;
          updateMappingUI();
          showToast(`已导入 ${Object.keys(data.placeholderToValue).length} 条映射记录`, 'success');
        } else {
          showToast('无效的映射文件格式', 'error');
        }
      } catch {
        showToast('映射文件解析失败，请检查文件格式', 'error');
      }
    };
    reader.readAsText(file);
    importFileInput.value = '';
  });

})();
