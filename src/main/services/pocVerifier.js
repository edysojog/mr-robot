const fs = require('fs');
const os = require('os');
const path = require('path');
const vm = require('vm');
const { spawn } = require('child_process');
const Anthropic = require('@anthropic-ai/sdk');
const Groq = require('groq-sdk');
const OpenAI = require('openai');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const { extractSnippet } = require('./fixAdvisor');
const { detectVulnClass, isPocEligible } = require('../../shared/pocClasses');

// Experimental, scoped narrowly on purpose: dynamic PoC verification for a
// fixed set of sink-mockable vuln classes in one runtime (a locked-down
// Docker container), not the general multi-language fuzzing-harness engine
// DeepAudit has. Auth/authz bypass, IDOR, and XSS are deliberately excluded --
// they need a live running app (or a browser/DOM context), not a single
// mocked function call, which is a different and heavier architecture than
// everything else here. See TODO.md's "deliberately out of scope" note.
const SANDBOX_IMAGE = 'node:20-alpine';
const CONTAINER_TIMEOUT_MS = 20 * 1000;
const HARNESS_TEMPERATURE = 0.1;
const HARNESS_MAX_TOKENS = 1500;

function checkDockerInstalled() {
  return new Promise((resolve) => {
    const child = spawn('docker', ['version', '--format', '{{.Server.Version}}'], { shell: true });
    let stdout = '';
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.on('error', () => resolve({ installed: false, version: null }));
    child.on('close', (code) => {
      if (code === 0 && stdout.trim()) {
        resolve({ installed: true, version: stdout.trim() });
      } else {
        resolve({ installed: false, version: null });
      }
    });
  });
}

function stripCodeFences(text) {
  const fenced = text.match(/```(?:javascript|js)?\n([\s\S]*?)```/);
  return (fenced ? fenced[1] : text).trim();
}

function checkSyntax(code) {
  try {
    new vm.Script(code);
    return null;
  } catch (err) {
    return err.message;
  }
}

// ---------------------------------------------------------------------------
// Standard classes: everything except the vulnerable-function reimplementation
// is fixed, hand-written code we own and test once -- the sink mock, the
// payload loop, breakout detection, and RESULT printing don't vary per LLM
// generation. The LLM only ever writes one function per class:
//
//   async function callVulnerable(payload, sink) { ... }
//
// which shrinks the space for it to introduce races, malformed mocks, or
// inconsistent verdict logic. Each class config below supplies the sink mock,
// the payload list, and the per-payload code that decides whether that
// payload "broke out" and pushes the boolean into `results`.
// ---------------------------------------------------------------------------

const STANDARD_CLASSES = {
  'command-injection': {
    payloads: ['; id', '| whoami', '$(id)', '`id`', 'harmless-control-value'],
    sinkMockCode: `
const __recorded = [];
const sink = {
  exec(command, optionsOrCb, maybeCb) {
    const callback = typeof optionsOrCb === 'function' ? optionsOrCb : maybeCb;
    __recorded.push(String(command));
    if (callback) setImmediate(() => callback(null, '', ''));
  },
  execSync(command) {
    __recorded.push(String(command));
    return '';
  },
  spawn(command, args) {
    __recorded.push([command, ...(args || [])].join(' '));
    return { on() {}, kill() {}, stdout: { on() {} }, stderr: { on() {} } };
  },
  execFile(file, argsOrCb, optionsOrCb, maybeCb) {
    const args = Array.isArray(argsOrCb) ? argsOrCb : [];
    const callback = typeof argsOrCb === 'function' ? argsOrCb : (typeof optionsOrCb === 'function' ? optionsOrCb : maybeCb);
    __recorded.push([file, ...args].join(' '));
    if (callback) setImmediate(() => callback(null, '', ''));
  },
  execFileSync(file, args) {
    __recorded.push([file, ...(args || [])].join(' '));
    return '';
  },
};`,
    perPayloadCheckCode: `
    const __cmd = __recorded[0] || '';
    results.push(payload !== 'harmless-control-value' && __cmd.includes(payload) && !__cmd.includes("'" + payload + "'") && !__cmd.includes('"' + payload + '"'));`,
    promptSinkDescription: `"sink" is an object shaped like Node's child_process module (exec, execSync, spawn, execFile, execFileSync), mocked to record the command it was given instead of running it.

1. Re-implement the vulnerable function INLINE, copying its logic faithfully from the source. Anywhere the source calls require('child_process') or uses a child_process/exec/spawn import, use "sink" instead.
2. Figure out the vulnerable function's real parameter shape. If it takes a plain value (a hostname, filename, etc.), call it directly with "payload". If it takes a request-handler-shaped parameter (e.g. (req, res), (ctx), (event, context)), build a minimal stub object with only the fields the function body actually reads (a stub req with .url/.query/.body/.params carrying "payload", a stub res with no-op writeHead/end/json/send/status).`,
  },

  'path-traversal': {
    payloads: ['../../../../etc/passwd', '../../../../../etc/shadow', '....//....//....//etc/passwd', 'report.pdf'],
    sinkMockCode: `
const __recorded = [];
function __rec(p) { __recorded.push(String(p)); }
const sink = {
  readFile(p, optsOrCb, maybeCb) { __rec(p); const cb = typeof optsOrCb === 'function' ? optsOrCb : maybeCb; if (cb) setImmediate(() => cb(null, Buffer.from(''))); },
  readFileSync(p) { __rec(p); return ''; },
  writeFile(p, data, optsOrCb, maybeCb) { __rec(p); const cb = typeof optsOrCb === 'function' ? optsOrCb : maybeCb; if (cb) setImmediate(() => cb(null)); },
  writeFileSync(p) { __rec(p); },
  unlink(p, cb) { __rec(p); if (cb) setImmediate(() => cb(null)); },
  unlinkSync(p) { __rec(p); },
  existsSync(p) { __rec(p); return false; },
  stat(p, cb) { __rec(p); if (cb) setImmediate(() => cb(new Error('ENOENT'))); },
  statSync(p) { __rec(p); throw new Error('ENOENT'); },
  createReadStream(p) { __rec(p); return { on() {}, pipe() { return this; } }; },
};
const __path = require('path');`,
    perPayloadCheckCode: `
    const __raw = __recorded[0];
    if (!__raw) {
      results.push(false); // sink never reached (e.g. safely rejected before touching fs) -- not a breakout
    } else {
      const __normalized = __path.normalize(__raw);
      results.push(payload !== 'report.pdf' && !__normalized.startsWith('/app/uploads/') && __normalized !== '/app/uploads');
    }`,
    promptSinkDescription: `"sink" is an object shaped like Node's fs module (readFile, readFileSync, writeFile, writeFileSync, unlink, unlinkSync, existsSync, stat, statSync, createReadStream), mocked to record the path it was given instead of touching the real filesystem.

1. Re-implement the vulnerable function INLINE. Anywhere the source calls require('fs') or uses an fs import, use "sink" instead. You may use the real, unmocked "path" module (require('path')) since it does no I/O.
2. The source's real base directory (whatever literal or variable it uses -- __dirname-relative, a config value, etc.) must be replaced with the literal string '/app/uploads' for this test. Join it with "payload" using the exact same method the source uses (path.join, path.resolve, or string concatenation) before passing the result to the sink.
3. Same parameter-shape rule as always: plain value vs. a stubbed (req, res)-shaped handler, whichever the source's real signature is.`,
  },

  ssrf: {
    payloads: ['http://169.254.169.254/latest/meta-data/', 'http://localhost:6379/', 'http://[::1]:22/', 'https://api.example.com/allowed'],
    sinkMockCode: `
const __recorded = [];
const sink = {
  request(url) { __recorded.push(String(url)); return Promise.resolve({ status: 200, ok: true, text: () => Promise.resolve(''), json: () => Promise.resolve({}) }); },
  get(url, cb) { __recorded.push(String(url)); if (cb) setImmediate(() => cb(null, { statusCode: 200 }, '')); return { on() {} }; },
};`,
    perPayloadCheckCode: `
    const __u = __recorded[0] || '';
    results.push(payload !== 'https://api.example.com/allowed' && __u.includes(payload));`,
    promptSinkDescription: `"sink" represents any outbound HTTP client (fetch, axios, http.get, https.get, request). It exposes sink.request(url) (returns a Promise, use for fetch/axios-style calls) and sink.get(url, callback) (use for http.get/https.get-style calls) -- both just record the URL instead of making a real request.

1. Re-implement the vulnerable function INLINE, replacing whichever real HTTP client call the source makes with the matching sink method, preserving how the URL is built from "payload" exactly as the source does (string concatenation, template literal, URL object, etc.).
2. Same parameter-shape rule as always for the function's own signature.`,
  },

  'sql-injection': {
    payloads: ["' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT NULL--", 'safe-username'],
    sinkMockCode: `
const __recorded = [];
const sink = {
  query(sql, paramsOrCb, maybeCb) {
    __recorded.push(String(sql));
    const callback = typeof paramsOrCb === 'function' ? paramsOrCb : maybeCb;
    if (callback) setImmediate(() => callback(null, []));
    return Promise.resolve([]);
  },
};`,
    perPayloadCheckCode: `
    const __q = __recorded[0] || '';
    results.push(payload !== 'safe-username' && __q.includes(payload));`,
    promptSinkDescription: `"sink" represents a DB client. It exposes sink.query(sqlString, paramsArrayOrCallback, callback) which records only the sqlString argument instead of running a real query.

1. Re-implement the vulnerable function INLINE, replacing the real DB client call with sink.query(...). Faithfully preserve HOW the source builds the query: if it string-concatenates "payload" directly into the SQL text, the payload will end up inside the sqlString you pass to sink.query. If it uses a parameterized placeholder (?, $1, etc.) and passes "payload" in a separate params array, then sqlString should contain the placeholder, NOT the payload -- pass payload only in the params array. Do not "fix" the source's behavior either way, just mirror it.
2. Same parameter-shape rule as always for the function's own signature.`,
  },

  'nosql-injection': {
    payloads: [{ $ne: null }, { $gt: '' }, { $regex: '.*', $options: 'i' }, 'safe-value'],
    sinkMockCode: `
const __recorded = [];
const sink = {
  find(filter, cb) { __recorded.push(filter); if (cb) setImmediate(() => cb(null, [])); return Promise.resolve([]); },
  findOne(filter, cb) { __recorded.push(filter); if (cb) setImmediate(() => cb(null, null)); return Promise.resolve(null); },
};
function __deepIncludesValue(obj, target) {
  if (obj === target) return true;
  if (typeof obj !== 'object' || obj === null) return false;
  for (const k of Object.keys(obj)) {
    try { if (JSON.stringify(obj[k]) === JSON.stringify(target)) return true; } catch (e) {}
    if (__deepIncludesValue(obj[k], target)) return true;
  }
  return false;
}`,
    perPayloadCheckCode: `
    const __filter = __recorded[0] || {};
    const __benign = payload === 'safe-value';
    results.push(!__benign && __deepIncludesValue(__filter, payload));`,
    promptSinkDescription: `"sink" represents a MongoDB-style collection. It exposes sink.find(filterObject, callback) and sink.findOne(filterObject, callback), which just record the filter object instead of querying a real database. "payload" for this class is sometimes an object (a MongoDB operator payload like {"$ne": null}), not a string.

1. Re-implement the vulnerable function INLINE, replacing the real DB call with sink.find(...) / sink.findOne(...). Build the filter object exactly as the source does -- e.g. if the source does db.collection.findOne({ username: req.body.username }) without checking that the field is a string, build { username: payload } and pass that object as-is (do not stringify or validate "payload" yourself -- that's exactly the bug being tested).
2. Same parameter-shape rule as always for the function's own signature.`,
  },

  'prototype-pollution': {
    payloads: ['{"__proto__":{"polluted":"yes"}}', '{"constructor":{"prototype":{"polluted":"yes"}}}', '{"a":{"__proto__":{"polluted":"yes"}}}', '{"safe":"value"}'],
    sinkMockCode: `
const __recorded = [];
const sink = { parse: JSON.parse };`,
    perPayloadCheckCode: `
    const __polluted = Object.prototype.polluted === 'yes';
    if (__polluted) delete Object.prototype.polluted;
    results.push(payload !== '{"safe":"value"}' && __polluted);`,
    promptSinkDescription: `"sink" exposes sink.parse, which is just the real JSON.parse (safe, no I/O) -- use it to parse "payload" the same way the source parses untrusted input (e.g. JSON.parse(req.body) or similar).

1. Re-implement the vulnerable MERGE/ASSIGN/SET function INLINE, copying its logic faithfully from the source -- this is usually a recursive deep-merge or a dynamic property setter that iterates Object.keys(source) and assigns target[key] = source[key] (or similar) without excluding __proto__/constructor/prototype.
2. Call sink.parse(payload) to get the untrusted object, then call your reimplemented merge/assign function with a FRESH plain object ({}) as the target and the parsed object as the source, exactly as the real source's call site does.`,
  },

  'insecure-deserialization': {
    payloads: ['process.mainModule.require("child_process").execSync("id")', 'require("fs").readFileSync("/etc/passwd","utf8")', '(function(){return 1+1})()', '1+1'],
    sinkMockCode: `
const __recorded = [];
const sink = {
  evalCode(code) { __recorded.push(String(code)); return undefined; },
};`,
    perPayloadCheckCode: `
    const __code = __recorded[0] || '';
    results.push(payload !== '1+1' && __code.includes(payload));`,
    promptSinkDescription: `"sink" exposes sink.evalCode(codeString), which records the string instead of executing it. This class covers any path where attacker-controlled data ends up executed as code during "deserialization" -- eval(), new Function(...)(...), vm.runInContext/runInNewContext, or a custom unserializer that ultimately evals a string.

1. Re-implement the vulnerable function INLINE. Wherever the source calls eval(x), new Function(...)(x), vm.runInContext(x, ...), or passes x into a custom deserializer that executes it, replace that exact call with sink.evalCode(x) instead -- do not actually eval anything yourself, just forward the same string the real code would have executed.
2. Same parameter-shape rule as always for the function's own signature.`,
  },

  xxe: {
    payloads: [
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
      '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
      '<?xml version="1.0"?><foo>hello</foo>',
    ],
    sinkMockCode: `
const __recorded = [];
const sink = {
  parseXml(xml, options) {
    const opts = options || {};
    __recorded.push({ xml: String(xml), externalEntitiesEnabled: !!opts.externalEntitiesEnabled });
    return {};
  },
};`,
    perPayloadCheckCode: `
    const __rec = __recorded[0];
    if (!__rec) {
      results.push(false); // sink never reached
    } else {
      const __benign = payload === '<?xml version="1.0"?><foo>hello</foo>';
      const __hasEntity = /<!ENTITY[\\s\\S]*SYSTEM/i.test(__rec.xml);
      results.push(!__benign && __hasEntity && __rec.externalEntitiesEnabled);
    }`,
    promptSinkDescription: `"sink" exposes sink.parseXml(xmlString, options), which records the string instead of actually parsing it. It represents any XML parser (libxmljs, xml2js, DOMParser, sax, etc.). "options" is a normalized shape YOU must fill in -- there is no real underlying parser here, so parser-library-specific option names (noent, dtdload, resolveExternalEntities, etc.) don't apply. options.externalEntitiesEnabled (boolean) is the one thing that matters: it must reflect whether the ACTUAL parser/config the source uses would resolve external entities and DTDs for this input.

1. Re-implement the vulnerable function INLINE, replacing the real XML-parsing call with sink.parseXml(payload, { externalEntitiesEnabled }). Determine externalEntitiesEnabled from what the source ACTUALLY does, not from the input string: true if the source uses default/vulnerable settings for a parser known to resolve external entities by default (e.g. many libxmljs configurations), or if it explicitly enables external entity/DTD resolution. false if the source explicitly disables external entity/DTD resolution, OR if it uses a library that does not resolve external entities by default (most modern Node XML libraries -- xml2js, fast-xml-parser, standard DOMParser -- are safe by default; only flag externalEntitiesEnabled true if the source's actual configuration would process the entity). Do NOT infer this from the payload string itself -- it's the same payload either way, the difference is entirely in the source's parser configuration.
2. If the source strips/validates/rejects DOCTYPE before parsing, replicate that faithfully by not calling sink.parseXml at all (or by stripping the DOCTYPE from the string first) so a hardened source correctly comes out NOT_VULNERABLE regardless of externalEntitiesEnabled.
3. Same parameter-shape rule as always for the function's own signature.`,
  },

  'open-redirect': {
    payloads: ['https://evil.example.net/phish', '//evil.example.net/phish', '/safe/relative/path'],
    sinkMockCode: `
const __recorded = [];
const sink = {
  redirect(location) { __recorded.push(String(location)); },
  setHeader(name, value) { if (String(name).toLowerCase() === 'location') __recorded.push(String(value)); },
};
const __urlMod = require('url');`,
    perPayloadCheckCode: `
    const __loc = __recorded[0] || '';
    const __benign = payload === '/safe/relative/path';
    const __derivesFromPayload = __loc.includes(payload);
    let __external = false;
    try {
      const __appHost = 'app.example.com';
      const __parsed = __urlMod.parse(__loc, false, true); // slashesDenoteHost -- catches //evil.example.net protocol-relative bypass
      __external = !!__parsed.host && __parsed.host !== __appHost;
    } catch (e) {}
    results.push(!__benign && __derivesFromPayload && __external);`,
    promptSinkDescription: `"sink" exposes sink.redirect(location) (for res.redirect(url)-style calls) and sink.setHeader(name, value) (for res.setHeader('Location', url) / res.writeHead(302, {Location: url})-style calls) -- use whichever matches the source, both just record the location instead of actually redirecting.

1. Re-implement the vulnerable function INLINE, replacing the real redirect call with the matching sink method, preserving how the destination is built from "payload" exactly as the source does.
2. Same parameter-shape rule as always for the function's own signature.`,
  },
};

function buildStandardHarnessPrefix(config) {
  return `'use strict';
${config.sinkMockCode}

const __PAYLOADS = ${JSON.stringify(config.payloads)};

function __settle(ticks) {
  return new Promise((resolve) => {
    let remaining = ticks;
    (function tick() {
      if (remaining-- <= 0) return resolve();
      setImmediate(tick);
    })();
  });
}

async function __main() {
  const results = [];
  for (const payload of __PAYLOADS) {
    __recorded.length = 0;
    try {
      await callVulnerable(payload, sink);
    } catch (err) {
      // A throw/rejection is not proof of safety -- judge on whatever got recorded.
    }
    await __settle(6);
${config.perPayloadCheckCode}
  }
  console.log(JSON.stringify(results));
  console.log('RESULT: ' + (results.includes(true) ? 'VULNERABLE' : 'NOT_VULNERABLE'));
}
`;
}

const STANDARD_HARNESS_SUFFIX = `
__main();
`;

function standardSystemPrompt(classId, config) {
  return `You are writing ONE piece of a PROOF-OF-CONCEPT VERIFIER for a single vulnerability class: ${classId}.

The driver, the mocked sink, the payload loop, and the verdict logic already exist and are fixed -- you do not write any of that. Your entire output is one JavaScript function with exactly this signature:

async function callVulnerable(payload, sink) { ... }

${config.promptSinkDescription}

Do not print anything. Do not define payloads, a loop, or a RESULT line -- the driver already does all of that. Output ONLY the raw "async function callVulnerable(payload, sink) { ... }" declaration and whatever helper code it needs above it. No markdown fences, no explanation before or after.`;
}

// ---------------------------------------------------------------------------
// ReDoS is architecturally different from the other classes: there's no sink
// to mock and no payload delivered into reimplemented application logic --
// the LLM just needs to locate and reproduce the vulnerable regex literal
// itself, and the fixed driver times how long it takes against a classic
// catastrophic-backtracking trigger vs. a same-length benign input, in a
// worker thread so a hang can be detected (and correctly read as VULNERABLE)
// instead of just killing the whole container and reporting inconclusive.
// ---------------------------------------------------------------------------

const REDOS_HARNESS = `'use strict';
const { Worker, isMainThread, workerData, parentPort } = require('worker_threads');

if (isMainThread) {
  async function __timeInput(source, flags, input) {
    const start = Date.now();
    const timedOut = await new Promise((resolve) => {
      const worker = new Worker(__filename, { workerData: { source, flags, input } });
      const timer = setTimeout(() => { worker.terminate(); resolve(true); }, 2000);
      worker.on('message', () => { clearTimeout(timer); resolve(false); });
      worker.on('error', () => { clearTimeout(timer); resolve(false); });
      worker.on('exit', () => { clearTimeout(timer); resolve(false); });
    });
    return { input, ms: Date.now() - start, timedOut };
  }

  async function __main() {
    const pattern = getVulnerablePattern();
    const source = pattern.source;
    const flags = pattern.flags;

    // Same-shaped input at two lengths, not "evil vs structurally different
    // benign" -- a benign/unrelated control (e.g. a bare run of 'a's with no
    // forced-failure tail) can itself fail to match plenty of real patterns
    // (anything requiring a literal character the control never contains,
    // like an '@' in an email regex) and trigger the SAME exponential
    // backtracking the long input is meant to probe, reading as a false
    // NOT_VULNERABLE when both time out. Comparing the same shape at a long
    // length (exponential blowup, if any, dominates) vs. a short length
    // (2^8 = 256 is trivial even for a genuinely vulnerable pattern) isolates
    // superlinear growth instead of "does this fail to match at all."
    const longInput = 'a'.repeat(35) + '!';
    const shortInput = 'a'.repeat(8) + '!';

    const longResult = await __timeInput(source, flags, longInput);
    const shortResult = await __timeInput(source, flags, shortInput);
    const results = [longResult, shortResult];
    const vulnerable = longResult.timedOut && !shortResult.timedOut;

    console.log(JSON.stringify(results));
    console.log('RESULT: ' + (vulnerable ? 'VULNERABLE' : 'NOT_VULNERABLE'));
  }

  __main();
} else {
  const re = new RegExp(workerData.source, workerData.flags);
  re.test(workerData.input);
  parentPort.postMessage('done');
}
`;

const REDOS_SYSTEM_PROMPT = `You are writing ONE piece of a PROOF-OF-CONCEPT VERIFIER for regular expression denial of service (ReDoS / catastrophic backtracking).

The driver already exists and is fixed -- it times how long the regex you identify takes against a crafted worst-case input vs. a same-length benign input, in a worker thread with a hard timeout, and prints the verdict. Your entire output is one JavaScript function with exactly this signature:

function getVulnerablePattern() { return /the-exact-pattern-from-the-source/flags; }

Find the vulnerable regular expression literal in the source you're given and return it EXACTLY as written there (same pattern text, same flags) -- do not simplify, fix, or rewrite it. If the source builds the pattern from a string (new RegExp(str)) with a hardcoded string literal, reconstruct the equivalent regex literal from that string.

Output ONLY the raw "function getVulnerablePattern() { return /.../; }" declaration. No markdown fences, no explanation before or after.`;

function validateRedosAdapter(adapterCode) {
  if (!/function\s+getVulnerablePattern\s*\(/.test(adapterCode)) {
    return 'Output does not define a getVulnerablePattern function.';
  }
  return checkSyntax(`${REDOS_HARNESS}\n${adapterCode}`);
}

function assembleRedosHarness(adapterCode) {
  return `${adapterCode}\n${REDOS_HARNESS}`;
}

// ---------------------------------------------------------------------------
// Shared plumbing: LLM call, syntax/structure validation with one retry,
// sandboxed execution, verdict parsing.
// ---------------------------------------------------------------------------

function isSupportedFile(finding) {
  return /\.(js|jsx|ts|tsx|mjs|cjs)$/i.test(finding.file || '');
}

async function callProvider({ provider, apiKey, model, ollamaBaseUrl, systemPrompt, userContent }) {
  if (provider === 'claude') {
    const client = new Anthropic({ apiKey });
    const response = await client.messages.create({
      model: model || 'claude-sonnet-5',
      max_tokens: HARNESS_MAX_TOKENS,
      temperature: HARNESS_TEMPERATURE,
      system: systemPrompt,
      messages: [{ role: 'user', content: userContent }],
    });
    return stripCodeFences(response.content.filter((b) => b.type === 'text').map((b) => b.text).join('\n'));
  }

  if (provider === 'groq') {
    const client = new Groq({ apiKey });
    const response = await client.chat.completions.create({
      model: model || 'llama-3.3-70b-versatile',
      temperature: HARNESS_TEMPERATURE,
      max_tokens: HARNESS_MAX_TOKENS,
      messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: userContent }],
    });
    return stripCodeFences(response.choices[0].message.content);
  }

  if (provider === 'gemini') {
    const client = new GoogleGenerativeAI(apiKey);
    const genModel = client.getGenerativeModel({ model: model || 'gemini-2.5-flash', systemInstruction: systemPrompt });
    const result = await genModel.generateContent({
      contents: [{ role: 'user', parts: [{ text: userContent }] }],
      generationConfig: { temperature: HARNESS_TEMPERATURE, maxOutputTokens: HARNESS_MAX_TOKENS },
    });
    return stripCodeFences(result.response.text());
  }

  if (provider === 'openai') {
    const client = new OpenAI({ apiKey });
    const response = await client.chat.completions.create({
      model: model || 'gpt-4.1-mini',
      temperature: HARNESS_TEMPERATURE,
      max_tokens: HARNESS_MAX_TOKENS,
      messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: userContent }],
    });
    return stripCodeFences(response.choices[0].message.content);
  }

  if (provider === 'ollama') {
    const client = new OpenAI({ apiKey: 'ollama', baseURL: ollamaBaseUrl });
    const response = await client.chat.completions.create({
      model: model || 'llama3.1',
      temperature: HARNESS_TEMPERATURE,
      messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: userContent }],
    });
    return stripCodeFences(response.choices[0].message.content);
  }

  throw new Error(`Unknown provider: ${provider}`);
}

function buildUserContent(finding, snippet, previousAttempt, previousError) {
  let userContent = `Finding: ${finding.title}\nLocation: ${finding.file}:${finding.line}\nDescription: ${finding.description || ''}\n\nSource (line-numbered):\n${snippet || '(source unavailable)'}`;
  if (previousAttempt) {
    userContent += `\n\nYour previous attempt, once dropped into the fixed driver, was rejected before it ever ran:\n\nError: ${previousError}\n\nPrevious attempt:\n${previousAttempt}\n\nFix the problem and output a corrected function. Follow the same instructions as before.`;
  }
  return userContent;
}

// Runs the harness in a locked-down, disposable container: no network,
// read-only bind mount, all Linux capabilities dropped, no privilege
// escalation, non-root, tight memory/CPU/time limits.
function runInSandbox(harnessCode) {
  return new Promise((resolve) => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mrrobotbot-poc-'));
    const scriptPath = path.join(tmpDir, 'harness.js');
    fs.writeFileSync(scriptPath, harnessCode, 'utf8');

    const args = [
      'run', '--rm',
      '--network', 'none',
      '--read-only',
      '--tmpfs', '/tmp:rw,size=32m',
      '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges',
      '--memory', '128m',
      '--cpus', '0.5',
      '--user', '1000:1000',
      '-v', `${tmpDir}:/workspace:ro`,
      SANDBOX_IMAGE,
      'node', '/workspace/harness.js',
    ];

    let settled = false;
    const child = spawn('docker', args, { shell: true });
    let stdout = '';
    let stderr = '';

    const timer = setTimeout(() => {
      if (settled) return;
      child.kill();
    }, CONTAINER_TIMEOUT_MS);

    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });

    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fs.rmSync(tmpDir, { recursive: true, force: true });
      resolve({ stdout: stdout.slice(0, 4000), stderr: stderr.slice(0, 2000), exitCode: code });
    });

    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fs.rmSync(tmpDir, { recursive: true, force: true });
      resolve({ stdout: '', stderr: err.message, exitCode: -1 });
    });
  });
}

function parseVerdict(stdout) {
  const match = stdout.match(/RESULT:\s*(VULNERABLE|NOT_VULNERABLE)/);
  return match ? match[1] : 'INCONCLUSIVE';
}

async function verifyFinding({ provider, apiKey, model, ollamaBaseUrl, rootDir, finding }) {
  const cls = detectVulnClass(finding);
  if (!cls) {
    throw new Error('Sandboxed PoC verification does not support this finding\'s vulnerability class or file type yet.');
  }

  const docker = await checkDockerInstalled();
  if (!docker.installed) {
    throw new Error('Docker is not available. Sandboxed PoC verification needs Docker installed and running.');
  }

  const snippet = extractSnippet(rootDir, finding);
  const isRedos = cls.id === 'redos';
  const config = isRedos ? null : STANDARD_CLASSES[cls.id];
  const systemPrompt = isRedos ? REDOS_SYSTEM_PROMPT : standardSystemPrompt(cls.id, config);
  const validate = isRedos ? validateRedosAdapter : (adapter) => {
    if (!/callVulnerable\s*[=(]|function\s+callVulnerable\s*\(/.test(adapter)) {
      return 'Output does not define a callVulnerable function.';
    }
    return checkSyntax(`${buildStandardHarnessPrefix(config)}\n${adapter}\n${STANDARD_HARNESS_SUFFIX}`);
  };
  const assemble = isRedos ? assembleRedosHarness : (adapter) => `${buildStandardHarnessPrefix(config)}\n${adapter}\n${STANDARD_HARNESS_SUFFIX}`;

  let adapter = await callProvider({ provider, apiKey, model, ollamaBaseUrl, systemPrompt, userContent: buildUserContent(finding, snippet) });
  let validationError = validate(adapter);
  let retried = false;

  if (validationError) {
    retried = true;
    const previousAttempt = adapter;
    adapter = await callProvider({ provider, apiKey, model, ollamaBaseUrl, systemPrompt, userContent: buildUserContent(finding, snippet, previousAttempt, validationError) });
    validationError = validate(adapter);
  }

  if (validationError) {
    throw new Error(`Generated PoC adapter is invalid after one retry: ${validationError}`);
  }

  const harness = assemble(adapter);
  const { stdout, stderr, exitCode } = await runInSandbox(harness);
  const verdict = parseVerdict(stdout);

  return { verdict, harness, stdout, stderr, exitCode, retried, vulnClass: cls.id };
}

module.exports = { checkDockerInstalled, verifyFinding, isPocEligible, isSupportedFile };
