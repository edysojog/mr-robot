const Anthropic = require('@anthropic-ai/sdk');
const { RECON_SYSTEM_PROMPT, SCANNER_SYSTEM_PROMPT, VERIFIER_SYSTEM_PROMPT } = require('../constants/systemPrompt');
const {
  AUDITOR_TEMPERATURE,
  REPORT_FINDINGS_SCHEMA,
  VERIFY_FINDINGS_SCHEMA,
  RECON_SCHEMA,
  readFileForPrompt,
  prioritizeFiles,
  batchByTokens,
  estimateTotalBatches,
  buildBatchUserContent,
  buildVerificationUserContent,
  buildReconUserContent,
  reconPriorityAsFindings,
  applyVerdicts,
  toFinding,
} = require('./auditorShared');

const DEFAULT_MODEL = 'claude-sonnet-5';

const REPORT_FINDINGS_TOOL = {
  name: 'report_findings',
  description: 'Report the security findings identified in this batch of files.',
  input_schema: REPORT_FINDINGS_SCHEMA,
};

const VERIFY_FINDINGS_TOOL = {
  name: 'verify_findings',
  description: 'Report a confirm/reject verdict for every candidate finding.',
  input_schema: VERIFY_FINDINGS_SCHEMA,
};

const REPORT_RECON_TOOL = {
  name: 'report_recon',
  description: 'Report the codebase summary and priority files for the scanner stage.',
  input_schema: RECON_SCHEMA,
};

class AnthropicAuditor {
  constructor(apiKey, model, verify = true, recon = true) {
    this.client = new Anthropic({ apiKey });
    this.model = model || DEFAULT_MODEL;
    this.verify = verify;
    this.recon = recon;
  }

  // Runs once per scan, before batching -- a lightweight map of the
  // codebase's attack surface that gets folded into every scanner batch's
  // context and boosts priority files the same way Semgrep-flagged files
  // already are. Failure here shouldn't block the scan, so it fails soft.
  async runRecon(files, emit) {
    if (!this.recon || files.length === 0) return { summary: null, priorityFiles: [] };

    emit('Claude recon: mapping codebase attack surface…');
    try {
      const response = await this.client.messages.create({
        model: this.model,
        max_tokens: 1024,
        temperature: AUDITOR_TEMPERATURE,
        system: RECON_SYSTEM_PROMPT,
        tools: [REPORT_RECON_TOOL],
        tool_choice: { type: 'tool', name: 'report_recon' },
        messages: [{ role: 'user', content: buildReconUserContent(files) }],
      });

      const toolUse = response.content.find((block) => block.type === 'tool_use');
      const summary = (toolUse && toolUse.input && toolUse.input.summary) || null;
      const priorityFiles = (toolUse && toolUse.input && toolUse.input.priorityFiles) || [];
      emit(`Claude recon finished: ${priorityFiles.length} priority file(s) identified`);
      return { summary, priorityFiles };
    } catch (err) {
      emit(`Claude recon failed (${err.message}) -- continuing without it`);
      return { summary: null, priorityFiles: [] };
    }
  }

  async review(files, semgrepFindings, onProgress) {
    const emit = (msg) => { if (onProgress) onProgress(msg); };

    const { summary: reconSummary, priorityFiles } = await this.runRecon(files, emit);
    const priorityContext = [...semgrepFindings, ...reconPriorityAsFindings(priorityFiles)];

    const selected = prioritizeFiles(files, priorityContext);
    if (selected.length === 0) {
      emit('no files eligible for the Claude pass');
      return { findings: [], batchCount: 0, partial: false };
    }

    const fileTexts = selected.map((f) => ({ file: f, text: readFileForPrompt(f) }));
    const batches = batchByTokens(fileTexts);
    const partial = batches.length < estimateTotalBatches(fileTexts);

    emit(`sending ${selected.length} file(s) to Claude in ${batches.length} batch(es)`);

    const allFindings = [];

    for (let i = 0; i < batches.length; i += 1) {
      emit(`Claude scanner batch ${i + 1}/${batches.length}…`);
      const userContent = buildBatchUserContent(batches[i], semgrepFindings, reconSummary);

      let candidates = [];
      try {
        const response = await this.client.messages.create({
          model: this.model,
          max_tokens: 4096,
          temperature: AUDITOR_TEMPERATURE,
          system: SCANNER_SYSTEM_PROMPT,
          tools: [REPORT_FINDINGS_TOOL],
          tool_choice: { type: 'tool', name: 'report_findings' },
          messages: [{ role: 'user', content: userContent }],
        });

        const toolUse = response.content.find((block) => block.type === 'tool_use');
        const findings = (toolUse && toolUse.input && toolUse.input.findings) || [];
        candidates = findings.map((f) => toFinding('claude', f));
      } catch (err) {
        emit(`Claude scanner batch ${i + 1} failed: ${err.message}`);
        continue;
      }

      if (!this.verify || candidates.length === 0) {
        allFindings.push(...candidates);
        continue;
      }

      emit(`Claude verifier batch ${i + 1}/${batches.length}: checking ${candidates.length} candidate(s)…`);
      try {
        const verifyContent = buildVerificationUserContent(batches[i], candidates);
        const response = await this.client.messages.create({
          model: this.model,
          max_tokens: 4096,
          temperature: AUDITOR_TEMPERATURE,
          system: VERIFIER_SYSTEM_PROMPT,
          tools: [VERIFY_FINDINGS_TOOL],
          tool_choice: { type: 'tool', name: 'verify_findings' },
          messages: [{ role: 'user', content: verifyContent }],
        });

        const toolUse = response.content.find((block) => block.type === 'tool_use');
        const verdicts = (toolUse && toolUse.input && toolUse.input.verdicts) || [];
        const confirmed = applyVerdicts(candidates, verdicts);
        emit(`Claude verifier batch ${i + 1}/${batches.length}: ${confirmed.length}/${candidates.length} confirmed`);
        allFindings.push(...confirmed);
      } catch (err) {
        // Verification failing shouldn't silently drop real findings --
        // fall back to reporting the unverified candidates rather than losing them.
        emit(`Claude verifier batch ${i + 1} failed (${err.message}) -- reporting unverified`);
        allFindings.push(...candidates);
      }
    }

    emit(`Claude pass finished: ${allFindings.length} finding(s)`);
    return { findings: allFindings, batchCount: batches.length, partial };
  }
}

module.exports = { AnthropicAuditor, DEFAULT_MODEL };
