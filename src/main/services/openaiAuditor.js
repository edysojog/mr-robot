const OpenAI = require('openai');
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

const DEFAULT_MODEL = 'gpt-4.1-mini';

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

// Same review() interface as AnthropicAuditor/GroqAuditor; OpenAI's chat
// completions + function calling shape is what Groq's API itself mirrors,
// so this is close to identical to groqAuditor.js minus Groq's rate-limit
// batch-size clamp -- OpenAI's paid tier has much higher token limits.
class OpenAIAuditor {
  // `label` is what progress lines call this pass. It is a field rather than
  // a literal so subclasses pointing the same OpenAI-compatible client at a
  // different endpoint (DeepSeek, and Ollama if it is ever folded in here)
  // report their own name instead of claiming to be OpenAI.
  constructor(apiKey, model, verify = true, recon = true) {
    this.client = new OpenAI({ apiKey });
    this.model = model || DEFAULT_MODEL;
    this.verify = verify;
    this.recon = recon;
    this.label = 'OpenAI';
    // The `source` stamped on findings from this class. A field like `label`
    // so subclasses (DeepSeek) report their own provider id instead of
    // mislabeling their findings as openai's.
    this.sourceId = 'openai';
  }

  async runRecon(files, emit) {
    if (!this.recon || files.length === 0) return { summary: null, priorityFiles: [] };

    emit(`${this.label} recon: mapping codebase attack surface…`);
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
      emit(`${this.label} recon finished: ${priorityFiles.length} priority file(s) identified`);
      return { summary, priorityFiles };
    } catch (err) {
      emit(`${this.label} recon failed (${err.message}) -- continuing without it`);
      return { summary: null, priorityFiles: [] };
    }
  }

  async review(files, semgrepFindings, onProgress) {
    const emit = (msg) => { if (onProgress) onProgress(msg); };

    const { summary: reconSummary, priorityFiles } = await this.runRecon(files, emit);
    const priorityContext = [...semgrepFindings, ...reconPriorityAsFindings(priorityFiles)];

    const selected = prioritizeFiles(files, priorityContext);
    if (selected.length === 0) {
      emit(`no files eligible for the ${this.label} pass`);
      return { findings: [], batchCount: 0, partial: false };
    }

    const fileTexts = selected.map((f) => ({ file: f, text: readFileForPrompt(f) }));
    const batches = batchByTokens(fileTexts);
    const partial = batches.length < estimateTotalBatches(fileTexts);

    emit(`sending ${selected.length} file(s) to ${this.label} in ${batches.length} batch(es)`);

    const allFindings = [];

    for (let i = 0; i < batches.length; i += 1) {
      emit(`${this.label} scanner batch ${i + 1}/${batches.length}…`);
      const userContent = buildBatchUserContent(batches[i], semgrepFindings, reconSummary);

      let candidates = [];
      try {
        const response = await this.client.chat.completions.create({
          model: this.model,
          max_tokens: 4096,
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
        candidates = (parsed.findings || []).map((f) => toFinding(this.sourceId, f));
      } catch (err) {
        emit(`${this.label} scanner batch ${i + 1} failed: ${err.message}`);
        continue;
      }

      if (!this.verify || candidates.length === 0) {
        allFindings.push(...candidates);
        continue;
      }

      emit(`${this.label} verifier batch ${i + 1}/${batches.length}: checking ${candidates.length} candidate(s)…`);
      try {
        const verifyContent = buildVerificationUserContent(batches[i], candidates);
        const response = await this.client.chat.completions.create({
          model: this.model,
          max_tokens: 4096,
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
        emit(`${this.label} verifier batch ${i + 1}/${batches.length}: ${confirmed.length}/${candidates.length} confirmed`);
        allFindings.push(...confirmed);
      } catch (err) {
        emit(`${this.label} verifier batch ${i + 1} failed (${err.message}) -- reporting unverified`);
        allFindings.push(...candidates);
      }
    }

    emit(`${this.label} pass finished: ${allFindings.length} finding(s)`);
    return { findings: allFindings, batchCount: batches.length, partial };
  }
}

module.exports = { OpenAIAuditor, DEFAULT_MODEL };
