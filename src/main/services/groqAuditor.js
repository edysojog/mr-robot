const Groq = require('groq-sdk');
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

const DEFAULT_MODEL = 'llama-3.3-70b-versatile';

// Groq's free tier caps requests at 12k tokens/minute -- auditorShared's
// default 50k-token batch target (sized for Claude's much higher limits)
// blows straight through that and 413s, silently contributing 0 findings
// for the whole batch. 5k input + ~1.5k system prompt + 2k output leaves
// real headroom under 12k.
const GROQ_TOKENS_PER_BATCH = 5000;
const GROQ_MAX_OUTPUT_TOKENS = 2048;

const REPORT_FINDINGS_TOOL = {
  type: 'function',
  function: {
    name: 'report_findings',
    description: 'Report the security findings identified in this batch of files.',
    parameters: REPORT_FINDINGS_SCHEMA,
  },
};

const VERIFY_FINDINGS_TOOL = {
  type: 'function',
  function: {
    name: 'verify_findings',
    description: 'Report a confirm/reject verdict for every candidate finding.',
    parameters: VERIFY_FINDINGS_SCHEMA,
  },
};

const REPORT_RECON_TOOL = {
  type: 'function',
  function: {
    name: 'report_recon',
    description: 'Report the codebase summary and priority files for the scanner stage.',
    parameters: RECON_SCHEMA,
  },
};

// Free-tier stand-in for AnthropicAuditor, same review() interface. Groq's
// API is OpenAI-compatible (chat completions + function calling) rather
// than Anthropic's tool_use format, so the request/response shape here
// differs even though the surrounding batching logic is shared.
class GroqAuditor {
  constructor(apiKey, model, verify = true, recon = true) {
    this.client = new Groq({ apiKey });
    this.model = model || DEFAULT_MODEL;
    this.verify = verify;
    this.recon = recon;
  }

  async runRecon(files, emit) {
    if (!this.recon || files.length === 0) return { summary: null, priorityFiles: [] };

    emit('Groq recon: mapping codebase attack surface…');
    try {
      const response = await this.client.chat.completions.create({
        model: this.model,
        max_tokens: 1024,
        temperature: AUDITOR_TEMPERATURE,
        tools: [REPORT_RECON_TOOL],
        tool_choice: { type: 'function', function: { name: 'report_recon' } },
        messages: [
          { role: 'system', content: RECON_SYSTEM_PROMPT },
          { role: 'user', content: buildReconUserContent(files) },
        ],
      });

      const toolCall = response.choices[0].message.tool_calls?.[0];
      const parsed = toolCall ? JSON.parse(toolCall.function.arguments) : {};
      const summary = parsed.summary || null;
      const priorityFiles = parsed.priorityFiles || [];
      emit(`Groq recon finished: ${priorityFiles.length} priority file(s) identified`);
      return { summary, priorityFiles };
    } catch (err) {
      emit(`Groq recon failed (${err.message}) -- continuing without it`);
      return { summary: null, priorityFiles: [] };
    }
  }

  async review(files, semgrepFindings, onProgress) {
    const emit = (msg) => { if (onProgress) onProgress(msg); };

    const { summary: reconSummary, priorityFiles } = await this.runRecon(files, emit);
    const priorityContext = [...semgrepFindings, ...reconPriorityAsFindings(priorityFiles)];

    const selected = prioritizeFiles(files, priorityContext);
    if (selected.length === 0) {
      emit('no files eligible for the Groq pass');
      return { findings: [], batchCount: 0, partial: false };
    }

    const fileTexts = selected.map((f) => ({ file: f, text: readFileForPrompt(f) }));
    const batches = batchByTokens(fileTexts, GROQ_TOKENS_PER_BATCH);
    const partial = batches.length < estimateTotalBatches(fileTexts, GROQ_TOKENS_PER_BATCH);

    emit(`sending ${selected.length} file(s) to Groq in ${batches.length} batch(es)`);

    const allFindings = [];

    for (let i = 0; i < batches.length; i += 1) {
      emit(`Groq scanner batch ${i + 1}/${batches.length}…`);
      const userContent = buildBatchUserContent(batches[i], semgrepFindings, reconSummary);

      let candidates = [];
      try {
        const response = await this.client.chat.completions.create({
          model: this.model,
          max_tokens: GROQ_MAX_OUTPUT_TOKENS,
          temperature: AUDITOR_TEMPERATURE,
          tools: [REPORT_FINDINGS_TOOL],
          tool_choice: { type: 'function', function: { name: 'report_findings' } },
          messages: [
            { role: 'system', content: SCANNER_SYSTEM_PROMPT },
            { role: 'user', content: userContent },
          ],
        });

        const toolCall = response.choices[0].message.tool_calls?.[0];
        const parsed = toolCall ? JSON.parse(toolCall.function.arguments) : { findings: [] };
        candidates = (parsed.findings || []).map((f) => toFinding('claude', f));
      } catch (err) {
        emit(`Groq scanner batch ${i + 1} failed: ${err.message}`);
        continue;
      }

      if (!this.verify || candidates.length === 0) {
        allFindings.push(...candidates);
        continue;
      }

      emit(`Groq verifier batch ${i + 1}/${batches.length}: checking ${candidates.length} candidate(s)…`);
      try {
        const verifyContent = buildVerificationUserContent(batches[i], candidates);
        const response = await this.client.chat.completions.create({
          model: this.model,
          max_tokens: GROQ_MAX_OUTPUT_TOKENS,
          temperature: AUDITOR_TEMPERATURE,
          tools: [VERIFY_FINDINGS_TOOL],
          tool_choice: { type: 'function', function: { name: 'verify_findings' } },
          messages: [
            { role: 'system', content: VERIFIER_SYSTEM_PROMPT },
            { role: 'user', content: verifyContent },
          ],
        });

        const toolCall = response.choices[0].message.tool_calls?.[0];
        const parsed = toolCall ? JSON.parse(toolCall.function.arguments) : { verdicts: [] };
        const confirmed = applyVerdicts(candidates, parsed.verdicts || []);
        emit(`Groq verifier batch ${i + 1}/${batches.length}: ${confirmed.length}/${candidates.length} confirmed`);
        allFindings.push(...confirmed);
      } catch (err) {
        emit(`Groq verifier batch ${i + 1} failed (${err.message}) -- reporting unverified`);
        allFindings.push(...candidates);
      }
    }

    emit(`Groq pass finished: ${allFindings.length} finding(s)`);
    return { findings: allFindings, batchCount: batches.length, partial };
  }
}

module.exports = { GroqAuditor, DEFAULT_MODEL };
