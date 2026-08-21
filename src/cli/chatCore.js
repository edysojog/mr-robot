// Shared, UI-agnostic chat engine: ChatSession (tool implementations, the
// Claude/Groq agentic turn loop) plus the ANSI-based render helpers used by
// both front-ends -- src/cli/chat.js (Node + Ink, requires this via CJS
// require()) and src/cli/chatOpentui.tsx (Bun + OpenTUI/SolidJS, also
// requires this via CJS -- Bun supports require() from a .tsx entry just
// fine). Kept here so neither front-end's rewrite risks drifting the tool
// logic itself, which is the part that actually has to stay correct.

const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');
const Anthropic = require('@anthropic-ai/sdk');
const Groq = require('groq-sdk');

const fileWalker = require('../main/services/fileWalker');
const semgrepRunner = require('../main/services/semgrepRunner');
const gitleaksRunner = require('../main/services/gitleaksRunner');
const npmAuditRunner = require('../main/services/npmAuditRunner');
const gitDiff = require('../main/services/gitDiff');
const findingsMerger = require('../main/services/findingsMerger');
const { AnthropicAuditor } = require('../main/services/claudeAuditor');
const { GroqAuditor } = require('../main/services/groqAuditor');
const chatService = require('../main/services/chatService');

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
// ANSI, kept minimal -- this runs in whatever terminal the user has open,
// not a styled Electron renderer.
const dim = (s) => `\x1b[2m${s}\x1b[0m`;
const bold = (s) => `\x1b[1m${s}\x1b[0m`;
const green = (s) => `\x1b[32m${s}\x1b[0m`;
const red = (s) => `\x1b[31m${s}\x1b[0m`;
const yellow = (s) => `\x1b[33m${s}\x1b[0m`;
const blue = (s) => `\x1b[34m${s}\x1b[0m`;
const brightRed = (s) => `\x1b[91m${s}\x1b[0m`;
const gray = (s) => `\x1b[90m${s}\x1b[0m`;

const SEVERITY_COLOR = { critical: brightRed, high: red, medium: yellow, low: blue, info: gray };
const severityColor = (sev) => (SEVERITY_COLOR[sev] || dim)(sev.toUpperCase());

// All tool/log output goes through this instead of process.stdout.write
// directly, so a front-end can route it into its own scrollback region
// rather than raw stdout. Plain process.stdout.write by default so
// ChatSession stays directly usable/testable without any UI wired up.
//
// The second argument is a semantic kind -- 'tool' (a tool is about to
// run), 'tool-result' (what it returned), or 'log' (incidental progress
// chatter from a long-running tool). A third carries metadata, currently
// just { tool } so a front-end can pick a per-tool icon. Front-ends that
// draw gutter markers need this; ones that don't can ignore both, which
// is why they're extra parameters rather than baked into the string.
let writeOut = (s) => process.stdout.write(s);

const check = (s) => green('✓ ') + s;
const cross = (s) => red('✗ ') + s;
const ARROW = dim('→ ');

function visibleLength(str) {
  // eslint-disable-next-line no-control-regex
  return str.replace(/\x1b\[[0-9;]*m/g, '').length;
}

// Boxed card, roughly matching the "VULNERABILITY CONFIRMED" card style --
// a titled box with label: value lines, width sized to content (capped so
// long descriptions wrap instead of stretching the box off-screen).
const BOX_MAX_WIDTH = 96;

function wrapLine(line, width) {
  if (visibleLength(line) <= width) return [line];
  const words = line.split(' ');
  const out = [];
  let current = '';
  for (const word of words) {
    const candidate = current ? `${current} ${word}` : word;
    if (visibleLength(candidate) > width && current) {
      out.push(current);
      current = word;
    } else {
      current = candidate;
    }
  }
  if (current) out.push(current);
  return out;
}

function renderBox(title, lines, borderColor = dim) {
  const wrapped = lines.flatMap((l) => wrapLine(l, BOX_MAX_WIDTH));
  const contentWidth = Math.min(BOX_MAX_WIDTH, Math.max(visibleLength(title || ''), ...wrapped.map(visibleLength), 20));
  const top = borderColor(`┌─ ${bold(title || '')}${borderColor('─'.repeat(Math.max(0, contentWidth - visibleLength(title || '') + 1)))}┐`);
  const bottom = borderColor(`└${'─'.repeat(contentWidth + 3)}┘`);
  const body = wrapped.map((l) => `${borderColor('│')} ${l}${' '.repeat(Math.max(0, contentWidth - visibleLength(l)))} ${borderColor('│')}`);
  return [top, ...body, bottom].join('\n');
}

function findingCardLines(f, number) {
  return [
    `${bold(`#${number}`)}  ${severityColor(f.severity)}  ${f.title}`,
    `${dim('at')} ${f.file}:${f.line}${f.confirmedByBoth ? dim('  (confirmed by static + AI)') : ''}${f.verified ? dim('  (verified)') : ''}`,
    ...(f.description ? wrapLine(f.description, BOX_MAX_WIDTH - 2).slice(0, 3) : []),
  ];
}

function renderFindingCard(f, number) {
  return renderBox('FINDING', findingCardLines(f, number), SEVERITY_COLOR[f.severity] || dim);
}

const SAFE_TOOL_DEFS = [
  {
    name: 'scan_project',
    description:
      'Run a security scan (Semgrep + AI review, optionally Gitleaks secrets scan and npm audit dependency scan) on a folder and return a findings summary. Call this whenever the user asks to scan, check, or audit a project.',
    schema: {
      type: 'object',
      properties: {
        folder: { type: 'string', description: 'Path to scan. Omit to use the default folder for this session.' },
        diff: { type: 'boolean', description: 'Only scan files changed since the last git commit, instead of the whole folder.' },
        gitleaks: { type: 'boolean', description: 'Also run a secrets scan.' },
        deps: { type: 'boolean', description: 'Also run npm audit for dependency vulnerabilities.' },
      },
    },
  },
  {
    name: 'list_findings',
    description: 'List findings from the most recently completed scan in this session, optionally filtered by severity. Use this to look up a finding number before calling explain_finding, or when the user just wants a list.',
    schema: {
      type: 'object',
      properties: {
        severity: { type: 'string', enum: SEVERITY_ORDER, description: 'Only list findings at this severity.' },
      },
    },
  },
  {
    name: 'explain_finding',
    description:
      "Answer a follow-up question about one specific finding from the most recent scan, grounded in its actual source code. Never propose a fix -- this tool reports and discusses only.",
    schema: {
      type: 'object',
      properties: {
        findingNumber: { type: 'integer', description: 'The finding number as shown by list_findings or the scan summary (1-indexed).' },
        question: { type: 'string' },
      },
      required: ['findingNumber', 'question'],
    },
  },
];

// Only added to the session's tool list when --enable-validation is passed --
// these are the two tools that actually do something (send a real request,
// run a real command) instead of just reasoning over already-scanned code.
// Off by default; even when on, every call still goes through ChatSession's
// confirm() gate before it executes -- see toolHttpRequest/toolRunCommand.
const VALIDATION_TOOL_DEFS = [
  {
    name: 'http_request',
    description:
      "Send ONE real HTTP request to validate a finding against a running instance of the target app (e.g. confirm an endpoint really is unauthenticated, or that a payload really triggers an SSRF/IDOR). Only use this when the user has asked you to validate, prove, or test a finding against a live target -- not speculatively. The user is always asked to confirm the exact request before it's sent; if they decline, do not claim it was sent or invent a response.",
    schema: {
      type: 'object',
      properties: {
        method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] },
        url: { type: 'string', description: 'Full URL, e.g. http://localhost:3000/api/config' },
        headers: { type: 'object', description: 'Optional request headers as key/value pairs.' },
        body: { type: 'string', description: 'Optional request body.' },
        reason: { type: 'string', description: 'One sentence: exactly what this request is meant to prove.' },
      },
      required: ['method', 'url', 'reason'],
    },
  },
  {
    name: 'run_command',
    description:
      "Run ONE shell command on the user's own machine (not sandboxed) to validate a finding -- e.g. reproduce a command-injection or path-traversal PoC in a controlled way. Only use this when the user has asked you to validate, prove, or reproduce a finding, and prefer the narrowest command that proves the point. The user is always asked to confirm the exact command before it runs; if they decline, do not claim it was run or invent output.",
    schema: {
      type: 'object',
      properties: {
        command: { type: 'string' },
        cwd: { type: 'string', description: "Working directory. Defaults to this session's default folder." },
        reason: { type: 'string', description: 'One sentence: exactly what this command is meant to prove.' },
      },
      required: ['command', 'reason'],
    },
  },
];

const AGENT_SYSTEM_PROMPT_BASE = `You are MrRobotBot, a terminal security assistant for developers. This is a normal, open-ended chat session -- talk about anything the user brings up: general security/AppSec questions, how a vulnerability class works, best practices, code review of a snippet they paste in, or just conversation. You are not limited to only responding to scan/finding-related requests -- most turns won't involve a tool call at all, and that's expected.

You additionally have three tools for when the user wants to work with an actual scan of their code: scan_project (runs static analysis + an AI review pass on a folder and returns a findings summary), list_findings (lists findings from the most recent scan in this session, optionally by severity), and explain_finding (discusses one specific finding from the most recent scan, grounded in its actual code).

Rules for the tools specifically:
- When the user asks you to scan/check/audit a project, call scan_project. If they don't name a folder, omit the folder argument and the default for this session will be used.
- Never invent findings. If asked about a finding that doesn't exist in the most recent scan (or no scan has run yet), say so plainly and suggest running a scan first.
- When discussing a specific finding from a real scan, use explain_finding rather than answering from the summary alone -- it re-reads the actual source and gives a grounded answer.
- Don't propose a fix, patch, or diff for a specific finding from a scan, even if asked directly -- this tool reports and discusses actual findings only, so redirect to explaining the problem instead. This restriction is about scan findings specifically, not a ban on general remediation advice or discussing how a class of vulnerability is typically fixed in the abstract -- that's normal security conversation and entirely fine.

Keep replies concise and terminal-friendly: short paragraphs or a tight list, not long markdown documents.`;

const AGENT_SYSTEM_PROMPT_VALIDATION_ADDENDUM = `

You additionally have two validation tools: http_request (sends one real HTTP request against a target the user is running) and run_command (runs one real shell command on the user's own machine). Both are real actions with real side effects, not simulations.

Rules for these two tools specifically:
- Only use them when the user has explicitly asked you to validate, prove, test, or confirm a finding is really exploitable against a live target -- never speculatively, and never just because a finding exists.
- Before calling either, make sure you can state in one sentence (the "reason" field) exactly what the result will prove. If you can't, don't call it.
- The user will always be asked to confirm the exact request or command before it executes. If they decline, say so plainly and move on -- never claim it ran, never fabricate a response or output.
- Prefer the narrowest, least destructive request/command that proves the point (e.g. a single GET to check an auth bypass, not a batch of requests; a read-only command, not one that modifies state, unless the finding specifically requires it).
- These tools validate findings; they still never produce a fix, patch, or exploit meant to cause lasting damage.`;

function severityCounts(findings) {
  const counts = SEVERITY_ORDER.reduce((acc, s) => ({ ...acc, [s]: 0 }), {});
  findings.forEach((f) => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
  return counts;
}

// One-line "what's about to happen" trace shown before a tool actually
// runs -- printed regardless of outcome, so slow tools (scan_project,
// http_request) don't leave the terminal silent while they work.
function describeToolCall(name, input) {
  if (name === 'scan_project') return `${ARROW}scanning ${input.folder || '(default folder)'}…`;
  if (name === 'list_findings') return `${ARROW}listing findings${input.severity ? ` (${input.severity})` : ''}…`;
  if (name === 'explain_finding') return `${ARROW}looking into finding #${input.findingNumber}…`;
  if (name === 'http_request') return `${ARROW}${yellow(`${input.method} ${input.url}`)}`;
  if (name === 'run_command') return `${ARROW}${brightRed(input.command || '')}`;
  return `${ARROW}${name}(${JSON.stringify(input)})`;
}

// Structured, boxed rendering of a tool's result -- the terminal-card look,
// printed directly rather than left for the model to paraphrase in prose.
// Returns '' for tools with nothing worth boxing (the model's own reply
// covers it).
function renderToolResult(name, result) {
  if (result && result.error) return cross(result.error);
  if (result && result.declined) return dim(`  ${result.message}`);

  if (name === 'scan_project') {
    if (result.message) return dim(`  ${result.message}`);
    const counts = SEVERITY_ORDER.filter((s) => result.counts[s] > 0).map((s) => `${severityColor(s)} ${result.counts[s]}`).join('   ');
    const lines = [check(`scan complete: ${bold(String(result.totalFindings))} finding(s)`)];
    if (counts) lines.push('  ' + counts);
    const cards = (result.topFindings || []).slice(0, 5).map((f) => renderFindingCard(f, f.number));
    if (result.note) cards.push(dim(result.note));
    return [...lines, '', ...cards].join('\n');
  }

  if (name === 'list_findings') {
    if (result.totalMatching === 0) return dim('  no findings match.');
    return result.findings
      .map((f) => `  ${bold(`#${f.number}`)} ${severityColor(f.severity)}  ${f.title} ${dim(`(${f.file}:${f.line})`)}`)
      .join('\n');
  }

  if (name === 'explain_finding') {
    return renderBox('EXPLAIN', [`${bold(result.finding.title)}`, `${dim('at')} ${result.finding.file}:${result.finding.line}`]);
  }

  if (name === 'http_request') {
    if (typeof result.status !== 'number') return '';
    const okColor = result.status < 400 ? green : red;
    return check(`response: ${okColor(String(result.status))}`) + (result.bodyPreview ? `\n${dim(result.bodyPreview.slice(0, 300))}` : '');
  }

  if (name === 'run_command') {
    const line = result.exitCode === 0 ? check(`exit code 0`) : cross(`exit code ${result.exitCode}`);
    const out = [line];
    if (result.stdout) out.push(dim(result.stdout.slice(0, 500)));
    if (result.stderr) out.push(red(result.stderr.slice(0, 300)));
    return out.join('\n');
  }

  return '';
}

class ChatSession {
  constructor({ provider, apiKey, model, defaultCwd, enableValidation = false, confirmFn = null }) {
    this.provider = provider;
    this.apiKey = apiKey;
    this.model = model;
    this.defaultCwd = defaultCwd;
    this.enableValidation = enableValidation;
    // Defaults to always declining -- a caller (like the tool-logic smoke
    // test in this repo's history) that doesn't wire a real confirm prompt
    // should never accidentally let a dynamic action through.
    this.confirmFn = confirmFn || (async () => false);
    this.lastScan = null; // { folderPath, findings, summary }
    this.findingChatHistories = new Map(); // finding.id -> [{role, content}]
    this.toolDefs = enableValidation ? [...SAFE_TOOL_DEFS, ...VALIDATION_TOOL_DEFS] : SAFE_TOOL_DEFS;

    if (provider === 'claude') {
      this.client = new Anthropic({ apiKey });
    } else if (provider === 'groq') {
      this.client = new Groq({ apiKey });
    } else {
      throw new Error(`Unsupported chat provider: ${provider} (expected claude or groq)`);
    }
  }

  async runTool(name, input) {
    if (name === 'scan_project') return this.toolScanProject(input || {});
    if (name === 'list_findings') return this.toolListFindings(input || {});
    if (name === 'explain_finding') return this.toolExplainFinding(input || {});
    // Gated on enableValidation even though the tool list already excludes
    // these when it's off -- defense in depth against a model response
    // that names a tool it was never offered.
    if (name === 'http_request') {
      if (!this.enableValidation) return { error: 'http_request is not enabled for this session (start with --enable-validation).' };
      return this.toolHttpRequest(input || {});
    }
    if (name === 'run_command') {
      if (!this.enableValidation) return { error: 'run_command is not enabled for this session (start with --enable-validation).' };
      return this.toolRunCommand(input || {});
    }
    return { error: `Unknown tool: ${name}` };
  }

  // Shared by turnClaude/turnGroq: prints the "about to run" trace, executes
  // the tool, prints the boxed/structured result, and returns the raw
  // result for the model's tool_result message (unaffected by any of the
  // display formatting above).
  async runToolWithDisplay(name, input) {
    writeOut(describeToolCall(name, input) + '\n', 'tool', { tool: name });
    let result;
    try {
      result = await this.runTool(name, input);
    } catch (err) {
      result = { error: err.message };
    }
    const rendered = renderToolResult(name, result);
    if (rendered) writeOut(rendered + '\n', 'tool-result', { tool: name });
    return result;
  }

  async toolHttpRequest(input) {
    const { method, url, headers, body, reason } = input;
    if (!method || !url || !reason) return { error: 'method, url, and reason are required.' };

    const approved = await this.confirmFn(
      `\nThe agent wants to send a real HTTP request:\n  ${method} ${url}\n  reason: ${reason}\n  headers: ${JSON.stringify(headers || {})}\n  body: ${body || '(none)'}\nSend it?`
    );
    if (!approved) return { declined: true, message: 'The user declined to send this request. Do not claim it was sent or fabricate a response.' };

    if (typeof fetch !== 'function') {
      return { error: 'This Node.js version has no global fetch -- upgrade to Node 18+ to use http_request.' };
    }

    try {
      const response = await fetch(url, { method, headers: headers || undefined, body, signal: AbortSignal.timeout(10000) });
      const text = await response.text();
      return {
        status: response.status,
        headers: Object.fromEntries(response.headers.entries()),
        bodyPreview: text.slice(0, 2000),
      };
    } catch (err) {
      return { error: err.message };
    }
  }

  async toolRunCommand(input) {
    const { command, cwd, reason } = input;
    if (!command || !reason) return { error: 'command and reason are required.' };
    const workDir = cwd ? path.resolve(cwd) : this.defaultCwd;

    const approved = await this.confirmFn(
      `\nThe agent wants to run this command on YOUR machine:\n  ${command}\n  cwd: ${workDir}\n  reason: ${reason}\nRun it?`
    );
    if (!approved) return { declined: true, message: 'The user declined to run this command. Do not claim it was run or fabricate output.' };

    return new Promise((resolve) => {
      exec(command, { cwd: workDir, timeout: 15000, maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
        resolve({
          exitCode: err ? (typeof err.code === 'number' ? err.code : 1) : 0,
          timedOut: !!(err && err.killed && err.signal === 'SIGTERM'),
          stdout: (stdout || '').slice(0, 4000),
          stderr: (stderr || '').slice(0, 2000),
        });
      });
    });
  }

  async toolScanProject(input) {
    const folderPath = path.resolve(input.folder || this.defaultCwd);
    if (!fs.existsSync(folderPath)) {
      return { error: `Folder does not exist: ${folderPath}` };
    }

    let changedRelPaths = null;
    if (input.diff) {
      if (!(await gitDiff.isGitRepo(folderPath))) {
        return { error: `--diff-equivalent requested but ${folderPath} is not a git repository.` };
      }
      changedRelPaths = await gitDiff.getChangedFiles(folderPath);
      if (changedRelPaths.length === 0) {
        return { message: 'No changed files since the last commit -- nothing to scan.' };
      }
    }

    const semgrepTargets = changedRelPaths ? changedRelPaths.map((rel) => path.join(folderPath, rel)) : undefined;
    const log = (msg) => writeOut(dim(`  [scan] ${msg}\n`), 'log');

    const semgrepResult = await semgrepRunner.runScan(folderPath, log, semgrepTargets);
    let findings = [...semgrepResult.findings];

    if (input.gitleaks) {
      const result = await gitleaksRunner.runScan(folderPath, log);
      findings = findings.concat(result.findings);
    }
    if (input.deps) {
      const result = await npmAuditRunner.runScan(folderPath, log);
      findings = findings.concat(result.findings);
    }

    const auditFiles = changedRelPaths
      ? await fileWalker.filesFromList(folderPath, changedRelPaths)
      : (await fileWalker.walk(folderPath)).files;

    const AuditorClass = this.provider === 'groq' ? GroqAuditor : AnthropicAuditor;
    const auditor = new AuditorClass(this.apiKey, this.model, true, true, false);
    const aiResult = await auditor.review(auditFiles, findings, log);

    const merged = findingsMerger.merge(findings, aiResult.findings);
    this.lastScan = { folderPath, findings: merged, summary: { diffMode: !!input.diff, changedFileCount: changedRelPaths ? changedRelPaths.length : undefined } };
    this.findingChatHistories.clear();

    const counts = severityCounts(merged);
    return {
      folderPath,
      totalFindings: merged.length,
      counts,
      topFindings: merged.slice(0, 15).map((f, i) => ({
        number: i + 1,
        severity: f.severity,
        title: f.title,
        file: f.file,
        line: f.line,
        confirmedByBoth: f.source === 'both',
        verified: !!f.verified,
        description: f.description,
      })),
      note: merged.length > 15 ? `${merged.length - 15} more finding(s) not shown -- use list_findings to page through by severity.` : undefined,
    };
  }

  toolListFindings(input) {
    if (!this.lastScan) return { error: 'No scan has run yet in this session. Call scan_project first.' };

    const filtered = input.severity
      ? this.lastScan.findings.filter((f) => f.severity === input.severity)
      : this.lastScan.findings;

    return {
      totalMatching: filtered.length,
      findings: filtered.map((f) => {
        const number = this.lastScan.findings.indexOf(f) + 1;
        return { number, severity: f.severity, title: f.title, file: f.file, line: f.line, confirmedByBoth: f.source === 'both' };
      }),
    };
  }

  async toolExplainFinding(input) {
    if (!this.lastScan) return { error: 'No scan has run yet in this session. Call scan_project first.' };
    const finding = this.lastScan.findings[input.findingNumber - 1];
    if (!finding) return { error: `No finding numbered ${input.findingNumber} in the most recent scan (${this.lastScan.findings.length} total).` };
    if (!input.question || !input.question.trim()) return { error: 'question is required.' };

    if (!this.findingChatHistories.has(finding.id)) this.findingChatHistories.set(finding.id, []);
    const history = this.findingChatHistories.get(finding.id);

    const answer = await chatService.chat({
      provider: this.provider,
      apiKey: this.apiKey,
      model: this.model,
      rootDir: this.lastScan.folderPath,
      finding,
      history,
      question: input.question.trim(),
    });

    history.push({ role: 'user', content: input.question.trim() });
    history.push({ role: 'assistant', content: answer });

    return { finding: { number: input.findingNumber, title: finding.title, file: finding.file, line: finding.line }, answer };
  }

  get systemPrompt() {
    return this.enableValidation ? AGENT_SYSTEM_PROMPT_BASE + AGENT_SYSTEM_PROMPT_VALIDATION_ADDENDUM : AGENT_SYSTEM_PROMPT_BASE;
  }

  async turn(userText) {
    if (this.provider === 'claude') return this.turnClaude(userText);
    return this.turnGroq(userText);
  }

  async turnClaude(userText) {
    if (!this.messages) this.messages = [];
    this.messages.push({ role: 'user', content: userText });

    const tools = this.toolDefs.map((t) => ({ name: t.name, description: t.description, input_schema: t.schema }));

    // eslint-disable-next-line no-constant-condition
    while (true) {
      const response = await this.client.messages.create({
        model: this.model || 'claude-sonnet-5',
        max_tokens: 1536,
        temperature: 0.4,
        system: this.systemPrompt,
        tools,
        messages: this.messages,
      });

      this.messages.push({ role: 'assistant', content: response.content });
      const toolUses = response.content.filter((b) => b.type === 'tool_use');

      if (toolUses.length === 0) {
        return response.content.filter((b) => b.type === 'text').map((b) => b.text).join('\n');
      }

      const toolResults = [];
      for (const call of toolUses) {
        const result = await this.runToolWithDisplay(call.name, call.input);
        toolResults.push({ type: 'tool_result', tool_use_id: call.id, content: JSON.stringify(result) });
      }
      this.messages.push({ role: 'user', content: toolResults });
    }
  }

  async turnGroq(userText) {
    if (!this.messages) this.messages = [{ role: 'system', content: this.systemPrompt }];
    this.messages.push({ role: 'user', content: userText });

    const tools = this.toolDefs.map((t) => ({ type: 'function', function: { name: t.name, description: t.description, parameters: t.schema } }));

    // eslint-disable-next-line no-constant-condition
    while (true) {
      const response = await this.client.chat.completions.create({
        model: this.model || 'llama-3.3-70b-versatile',
        max_tokens: 1536,
        temperature: 0.4,
        tools,
        tool_choice: 'auto',
        messages: this.messages,
      });

      const msg = response.choices[0].message;
      this.messages.push(msg);

      if (!msg.tool_calls || msg.tool_calls.length === 0) {
        return msg.content || '';
      }

      for (const call of msg.tool_calls) {
        let args = {};
        try { args = JSON.parse(call.function.arguments || '{}'); } catch { /* malformed args from the model -- run with {} */ }
        const result = await this.runToolWithDisplay(call.function.name, args);
        this.messages.push({ role: 'tool', tool_call_id: call.id, content: JSON.stringify(result) });
      }
    }
  }
}

function resolveApiKey(provider, explicitKey) {
  if (explicitKey) return explicitKey;
  if (provider === 'claude') return process.env.ANTHROPIC_API_KEY || null;
  if (provider === 'groq') return process.env.GROQ_API_KEY || null;
  return null;
}


module.exports = {
  SEVERITY_ORDER,
  dim,
  bold,
  green,
  red,
  yellow,
  blue,
  brightRed,
  gray,
  severityColor,
  check,
  cross,
  ARROW,
  visibleLength,
  renderBox,
  renderFindingCard,
  SAFE_TOOL_DEFS,
  VALIDATION_TOOL_DEFS,
  describeToolCall,
  renderToolResult,
  ChatSession,
  resolveApiKey,
  setWriteOut: (fn) => { writeOut = fn; },
};
