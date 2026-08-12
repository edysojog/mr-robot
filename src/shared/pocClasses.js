// Registry of vulnerability classes the sandboxed PoC verifier can dynamically
// confirm. Lightweight and dependency-free on purpose -- both the main process
// (pocVerifier.js, to pick a harness template) and the renderer (results.js, to
// decide whether to show the "verify in sandbox" button) need this, and the
// renderer has no module system/bundler, just plain <script> tags.
//
// Each class only needs a way to *detect* it applies to a finding. The actual
// harness template (sink mock, payloads, detection heuristic, LLM prompt) lives
// in pocVerifier.js since it depends on Node/Docker/LLM SDKs the renderer can't load.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PocClasses = factory();
  }
})(typeof window !== 'undefined' ? window : this, function () {
  const JS_TS_EXTENSIONS = /\.(js|jsx|ts|tsx|mjs|cjs)$/i;

  // Order matters -- first match wins, so put more specific patterns first
  // (e.g. NoSQL before generic patterns that might overlap).
  const CLASSES = [
    {
      id: 'command-injection',
      label: 'OS command injection',
      textPattern: /command injection|child_process|child-process|os command|shell injection/,
      fileExtensions: JS_TS_EXTENSIONS,
    },
    {
      id: 'nosql-injection',
      label: 'NoSQL injection',
      textPattern: /nosql injection|mongo.*injection|mongodb.*injection/,
      fileExtensions: JS_TS_EXTENSIONS,
    },
    {
      id: 'sql-injection',
      label: 'SQL injection',
      textPattern: /sql injection|sqli\b/,
      fileExtensions: JS_TS_EXTENSIONS,
    },
    {
      id: 'path-traversal',
      label: 'Path traversal',
      textPattern: /path traversal|directory traversal|zip slip|arbitrary file (read|write)/,
      fileExtensions: JS_TS_EXTENSIONS,
    },
    {
      id: 'ssrf',
      label: 'Server-side request forgery',
      textPattern: /ssrf|server-side request forgery|server side request forgery/,
      fileExtensions: JS_TS_EXTENSIONS,
    },
    {
      id: 'xxe',
      label: 'XML external entity injection',
      textPattern: /xxe|xml external entity/,
      fileExtensions: JS_TS_EXTENSIONS,
    },
    {
      id: 'prototype-pollution',
      label: 'Prototype pollution',
      textPattern: /prototype pollution|proto pollution|__proto__/,
      fileExtensions: JS_TS_EXTENSIONS,
    },
    {
      id: 'insecure-deserialization',
      label: 'Insecure deserialization',
      textPattern: /insecure deserialization|unsafe deserialization|deserialization of untrusted data|unsafe eval|code injection/,
      fileExtensions: JS_TS_EXTENSIONS,
    },
    {
      id: 'open-redirect',
      label: 'Open redirect',
      textPattern: /open redirect|unvalidated redirect/,
      fileExtensions: JS_TS_EXTENSIONS,
    },
    {
      id: 'redos',
      label: 'Regular expression denial of service (ReDoS)',
      textPattern: /redos|regular expression denial of service|catastrophic backtracking|regex.*denial of service/,
      fileExtensions: JS_TS_EXTENSIONS,
    },
  ];

  function findingText(finding) {
    return `${finding.ruleId || ''} ${finding.title || ''} ${finding.description || ''}`.toLowerCase();
  }

  // Returns the matched class config, or null if no class + supported file type matches.
  function detectVulnClass(finding) {
    const text = findingText(finding);
    const file = finding.file || '';
    for (const cls of CLASSES) {
      if (cls.textPattern.test(text) && cls.fileExtensions.test(file)) {
        return cls;
      }
    }
    return null;
  }

  function isPocEligible(finding) {
    return detectVulnClass(finding) !== null;
  }

  return { CLASSES, detectVulnClass, isPocEligible };
});
