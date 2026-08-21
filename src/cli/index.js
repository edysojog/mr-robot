#!/usr/bin/env node
// Headless scan engine -- no Electron dependency, so this can run in CI.
// Reuses the exact same scan services the desktop app uses (fileWalker,
// semgrepRunner, claudeAuditor/groqAuditor/mockAuditor, findingsMerger,
// baselineStore, gitDiff, reportExporter) so CLI and GUI scans behave
// identically. Deliberately does not touch secureStore/localSettings/
// scanHistoryStore -- those are Electron-userData-backed and don't apply
// to an ephemeral CI run; API keys come from flags/env instead.

const path = require('path');
const fs = require('fs');

const fileWalker = require('../main/services/fileWalker');
const semgrepRunner = require('../main/services/semgrepRunner');
const gitleaksRunner = require('../main/services/gitleaksRunner');
const npmAuditRunner = require('../main/services/npmAuditRunner');
const osvRunner = require('../main/services/osvRunner');
const gitDiff = require('../main/services/gitDiff');
const findingsMerger = require('../main/services/findingsMerger');
const baselineStore = require('../main/services/baselineStore');
const reportExporter = require('../main/services/reportExporter');
const { AnthropicAuditor } = require('../main/services/claudeAuditor');
const { GroqAuditor } = require('../main/services/groqAuditor');
const { GeminiAuditor } = require('../main/services/geminiAuditor');
const { OpenAIAuditor } = require('../main/services/openaiAuditor');
const { DeepseekAuditor } = require('../main/services/deepseekAuditor');
const { OllamaAuditor, DEFAULT_BASE_URL: DEFAULT_OLLAMA_BASE_URL } = require('../main/services/ollamaAuditor');
const { MockAuditor } = require('../main/services/mockAuditor');

const KEYLESS_PROVIDERS = ['mock', 'ollama'];

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

const HELP = `
MrRobotBot CLI -- headless Semgrep + AI security scan

Usage:
  mrrobot audit <folder> [options]

Options:
  --diff                 Only scan files changed since the last commit (git required)
  --semgrep-only         Skip the AI pass entirely (fast, free, no API key -- for hooks/gates)
  --no-semgrep           Skip the Semgrep pass
  --gitleaks             Also run a Gitleaks secrets scan (needs gitleaks on PATH)
  --deps                 Also run npm audit for dependency vulnerabilities (needs package.json)
  --osv                  Also cross-reference pinned deps against OSV.dev (requirements.txt/go.mod/
                         Cargo.lock -- keyless public API, no local tool needed)
  --no-verify            Skip the verifier pass -- report the AI scanner's raw candidates unchecked
  --no-recon             Skip the recon pass -- no upfront codebase-mapping call before the scanner
  --specialists          Replace the single generalist scanner call per batch with four parallel
                         specialist calls (authz, injection, secrets/crypto, data/logic exposure).
                         Claude and Groq only; other providers ignore this flag for now. Roughly
                         4x's the scanner call count/cost per batch in exchange for narrower,
                         higher-recall prompts per vulnerability class.
  --provider <name>      mock | groq | claude | gemini | openai | deepseek | ollama
                         (default: mock)
  --model <name>         Model override for the selected provider (ollama has no universal
                         default -- use whatever you've already run "ollama pull" for)
  --api-key <key>        API key for groq/claude/gemini/openai/deepseek (or GROQ_API_KEY /
                         ANTHROPIC_API_KEY / GEMINI_API_KEY / OPENAI_API_KEY /
                         DEEPSEEK_API_KEY). Not needed for mock or ollama.
  --ollama-url <url>     Ollama server URL (default: http://localhost:11434/v1, or OLLAMA_BASE_URL)
  --format <fmt>         terminal | json | markdown | html | sarif
                         Default: terminal when printing to a terminal, json
                         when redirected, piped, or writing with --output.
  --output <path>        Write the report here instead of stdout
  --fail-on <severity>   critical | high | medium | low | info | none  (default: high)
                         Exit 1 if any finding at or above this severity is found.
  --help                 Show this help
`;

function parseArgs(argv) {
  // format is deliberately left unset rather than defaulted to 'json' here:
  // main() needs to distinguish "user asked for json" from "user said
  // nothing", since the latter picks the terminal report on a TTY.
  const args = { folder: null, diff: false, provider: 'mock', failOn: 'high' };
  const rest = [...argv];

  while (rest.length > 0) {
    const token = rest.shift();
    switch (token) {
      case '--diff': args.diff = true; break;
      case '--semgrep-only': args.semgrepOnly = true; break;
      case '--no-semgrep': args.noSemgrep = true; break;
      case '--gitleaks': args.gitleaks = true; break;
      case '--deps': args.deps = true; break;
      case '--osv': args.osv = true; break;
      case '--no-verify': args.noVerify = true; break;
      case '--no-recon': args.noRecon = true; break;
      case '--specialists': args.specialists = true; break;
      case '--provider': args.provider = rest.shift(); break;
      case '--model': args.model = rest.shift(); break;
      case '--api-key': args.apiKey = rest.shift(); break;
      case '--ollama-url': args.ollamaUrl = rest.shift(); break;
      case '--format': args.format = rest.shift(); break;
      case '--output': args.output = rest.shift(); break;
      case '--fail-on': args.failOn = rest.shift(); break;
      case '--help': case '-h': args.help = true; break;
      default:
        if (!args.folder && !token.startsWith('--')) args.folder = token;
    }
  }
  return args;
}

function log(message) {
  process.stderr.write(`[mrrobotbot] ${message}\n`);
}

function resolveApiKey(provider, explicitKey) {
  if (explicitKey) return explicitKey;
  if (provider === 'claude') return process.env.ANTHROPIC_API_KEY || null;
  if (provider === 'groq') return process.env.GROQ_API_KEY || null;
  if (provider === 'gemini') return process.env.GEMINI_API_KEY || null;
  if (provider === 'openai') return process.env.OPENAI_API_KEY || null;
  if (provider === 'deepseek') return process.env.DEEPSEEK_API_KEY || null;
  return null;
}

function resolveOllamaUrl(explicitUrl) {
  return explicitUrl || process.env.OLLAMA_BASE_URL || DEFAULT_OLLAMA_BASE_URL;
}

function buildAuditor(provider, apiKey, model, verify, recon, ollamaUrl, specialists) {
  if (provider === 'mock') return new MockAuditor(verify, recon);
  if (provider === 'groq') return new GroqAuditor(apiKey, model, verify, recon, specialists);
  if (provider === 'claude') return new AnthropicAuditor(apiKey, model, verify, recon, specialists);
  if (provider === 'gemini') return new GeminiAuditor(apiKey, model, verify, recon);
  if (provider === 'openai') return new OpenAIAuditor(apiKey, model, verify, recon);
  if (provider === 'ollama') return new OllamaAuditor(ollamaUrl, model, verify, recon);
  if (provider === 'deepseek') return new DeepseekAuditor(apiKey, model, verify, recon);
  throw new Error(`Unknown provider: ${provider} (expected mock, groq, claude, gemini, openai, deepseek, or ollama)`);
}

function severityAtOrAbove(findings, threshold) {
  if (threshold === 'none') return [];
  const thresholdRank = SEVERITY_ORDER.indexOf(threshold);
  if (thresholdRank === -1) throw new Error(`Invalid --fail-on value: ${threshold}`);
  return findings.filter((f) => SEVERITY_ORDER.indexOf(f.severity) <= thresholdRank);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help || !args.folder) {
    process.stdout.write(HELP);
    process.exit(args.help ? 0 : 2);
  }

  const folderPath = path.resolve(args.folder);
  if (!fs.existsSync(folderPath)) {
    log(`folder does not exist: ${folderPath}`);
    process.exit(2);
  }

  const apiKey = resolveApiKey(args.provider, args.apiKey);
  const ollamaUrl = resolveOllamaUrl(args.ollamaUrl);
  if (!args.semgrepOnly && !KEYLESS_PROVIDERS.includes(args.provider) && !apiKey) {
    const envVar = { claude: 'ANTHROPIC_API_KEY', groq: 'GROQ_API_KEY', gemini: 'GEMINI_API_KEY', openai: 'OPENAI_API_KEY', deepseek: 'DEEPSEEK_API_KEY' }[args.provider];
    log(`no API key for provider "${args.provider}" -- pass --api-key or set ${envVar || '(unknown provider)'}`);
    process.exit(2);
  }

  const runSemgrep = !args.noSemgrep;
  const runGitleaks = !!args.gitleaks;
  const runDeps = !!args.deps;
  const runOsv = !!args.osv;

  if (runSemgrep) {
    const semgrepStatus = await semgrepRunner.checkInstalled();
    if (!semgrepStatus.installed) {
      log('semgrep not found on PATH -- install with "pip install semgrep"');
      process.exit(2);
    }
  }
  if (runGitleaks) {
    const gitleaksStatus = await gitleaksRunner.checkInstalled();
    if (!gitleaksStatus.installed) {
      log('gitleaks not found on PATH -- install from github.com/gitleaks/gitleaks, or drop --gitleaks');
      process.exit(2);
    }
  }

  try {
    let changedRelPaths = null;
    if (args.diff) {
      if (!(await gitDiff.isGitRepo(folderPath))) {
        log(`--diff requested but ${folderPath} is not a git repository`);
        process.exit(2);
      }
      changedRelPaths = await gitDiff.getChangedFiles(folderPath);
      log(`${changedRelPaths.length} changed file(s) found`);
    }

    let findings = [];
    let summary;

    if (args.diff && changedRelPaths.length === 0) {
      summary = {
        folderPath, skippedCount: 0, findingCount: 0, diffMode: true,
        changedFileCount: 0, claudePartial: false, completedAt: new Date().toISOString(),
      };
      log('no changed files -- nothing to scan');
    } else {
      const semgrepTargets = changedRelPaths ? changedRelPaths.map((rel) => path.join(folderPath, rel)) : undefined;

      let semgrepFindings = [];
      let skippedCount = 0;
      if (runSemgrep) {
        log(`running semgrep (target: ${semgrepTargets ? `${semgrepTargets.length} file(s)` : folderPath})`);
        const result = await semgrepRunner.runScan(folderPath, log, semgrepTargets);
        semgrepFindings = result.findings;
        skippedCount = result.skippedCount;
      } else {
        log('skipping semgrep pass (--no-semgrep)');
      }

      let gitleaksFindings = [];
      if (runGitleaks) {
        log('running gitleaks');
        const result = await gitleaksRunner.runScan(folderPath, log);
        gitleaksFindings = result.findings;
      }

      let npmAuditFindings = [];
      if (runDeps) {
        log('running npm audit');
        const result = await npmAuditRunner.runScan(folderPath, log);
        npmAuditFindings = result.findings;
      }

      let osvFindings = [];
      if (runOsv) {
        log('running OSV dependency scan');
        const result = await osvRunner.runScan(folderPath, log);
        osvFindings = result.findings;
      }

      const staticFindings = [...semgrepFindings, ...gitleaksFindings, ...npmAuditFindings, ...osvFindings];

      let aiFindings = [];
      let claudePartial = false;
      if (args.semgrepOnly) {
        log('skipping AI pass (--semgrep-only)');
      } else {
        log(`running ${args.provider} pass`);
        const auditFiles = changedRelPaths
          ? await fileWalker.filesFromList(folderPath, changedRelPaths)
          : (await fileWalker.walk(folderPath)).files;

        const auditor = buildAuditor(args.provider, apiKey, args.model, !args.noVerify, !args.noRecon, ollamaUrl, !!args.specialists);
        const result = await auditor.review(auditFiles, staticFindings, log);
        aiFindings = result.findings;
        claudePartial = result.partial;
      }

      const merged = findingsMerger.merge(staticFindings, aiFindings);
      const { kept, suppressedCount } = baselineStore.filterSuppressed(folderPath, merged);
      findings = kept;

      summary = {
        folderPath, skippedCount, findingCount: kept.length, suppressedCount,
        diffMode: !!args.diff, changedFileCount: changedRelPaths ? changedRelPaths.length : undefined,
        claudePartial, completedAt: new Date().toISOString(),
      };
    }

    const model = reportExporter.buildReportModel(findings, summary);

    // Only stdout going to a real terminal gets the human-readable report.
    // Redirecting to a file, piping into jq, or writing with --output all
    // still default to JSON, so CI, the pre-commit hook and
    // `mrrobot audit . > report.json` behave exactly as before. An explicit
    // --format always wins over this.
    const interactive = !!process.stdout.isTTY && !args.output;
    const format = args.format || (interactive ? 'terminal' : 'json');
    // NO_COLOR is the de-facto opt-out (no-color.org).
    const useColor = !!process.stdout.isTTY && !process.env.NO_COLOR;

    const builders = {
      json: reportExporter.toJson,
      markdown: reportExporter.toMarkdown,
      html: reportExporter.toHtml,
      sarif: reportExporter.toSarif,
      terminal: (m) => reportExporter.toTerminal(m, { color: useColor, width: process.stdout.columns }),
    };
    const build = builders[format];
    if (!build) {
      log(`unknown --format: ${format} (expected terminal, json, markdown, html, or sarif)`);
      process.exit(2);
    }
    const content = build(model);

    if (args.output) {
      fs.writeFileSync(args.output, content, 'utf8');
      log(`report written to ${args.output}`);
    } else {
      process.stdout.write(content + '\n');
    }

    const blocking = severityAtOrAbove(findings, args.failOn);
    log(`${findings.length} finding(s) total, ${blocking.length} at or above "${args.failOn}"`);
    process.exit(blocking.length > 0 ? 1 : 0);
  } catch (err) {
    log(`scan failed: ${err.message}`);
    process.exit(2);
  }
}

main();
