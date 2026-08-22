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

const DEFAULT_BASE_URL = 'http://localhost:11434/v1';
// No universal default makes sense here -- unlike a hosted provider, the
// only valid model is whatever the user has already pulled locally
// (`ollama pull <model>`). This is a common one, not a guaranteed one.
const DEFAULT_MODEL = 'llama3.1';

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

// Local-only provider: Ollama exposes an OpenAI-compatible endpoint, so this
// reuses the openai SDK pointed at a local baseURL instead of api.openai.com.
// No API key is needed -- the SDK requires a non-empty string regardless, so
// a placeholder is passed and never actually checked by Ollama. Smaller/
// local models are noticeably weaker at reliable structured tool-calling
// than the hosted providers; failures here fail soft the same way every
// other auditor does (unverified/0-finding batch, not a crashed scan).
class OllamaAuditor {
  constructor(baseUrl, model, verify = true, recon = true) {
    this.client = new OpenAI({ apiKey: 'ollama', baseURL: baseUrl || DEFAULT_BASE_URL });
    this.model = model || DEFAULT_MODEL;
    this.verify = verify;
    this.recon = recon;
  }

  async runRecon(files, emit) {
    if (!this.recon || files.length === 0) return { summary: null, priorityFiles: [] };

    emit('Ollama recon: mapping codebase attack surface…');
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
      emit(`Ollama recon finished: ${priorityFiles.length} priority file(s) identified`);
      return { summary, priorityFiles };
    } catch (err) {
      emit(`Ollama recon failed (${err.message}) -- continuing without it`);
      return { summary: null, priorityFiles: [] };
    }
  }

  async review(files, semgrepFindings, onProgress) {
    const emit = (msg) => { if (onProgress) onProgress(msg); };

    const { summary: reconSummary, priorityFiles } = await this.runRecon(files, emit);
    const priorityContext = [...semgrepFindings, ...reconPriorityAsFindings(priorityFiles)];

    const selected = prioritizeFiles(files, priorityContext);
    if (selected.length === 0) {
      emit('no files eligible for the Ollama pass');
      return { findings: [], batchCount: 0, partial: false };
    }

    const fileTexts = selected.map((f) => ({ file: f, text: readFileForPrompt(f) }));
    const batches = batchByTokens(fileTexts);
    const partial = batches.length < estimateTotalBatches(fileTexts);

    emit(`sending ${selected.length} file(s) to Ollama (${this.model}) in ${batches.length} batch(es)`);

    const allFindings = [];

    for (let i = 0; i < batches.length; i += 1) {
      emit(`Ollama scanner batch ${i + 1}/${batches.length}…`);
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
        candidates = (parsed.findings || []).map((f) => toFinding('ollama', f));
      } catch (err) {
        emit(`Ollama scanner batch ${i + 1} failed: ${err.message}`);
        continue;
      }

      if (!this.verify || candidates.length === 0) {
        allFindings.push(...candidates);
        continue;
      }

      emit(`Ollama verifier batch ${i + 1}/${batches.length}: checking ${candidates.length} candidate(s)…`);
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
        emit(`Ollama verifier batch ${i + 1}/${batches.length}: ${confirmed.length}/${candidates.length} confirmed`);
        allFindings.push(...confirmed);
      } catch (err) {
        emit(`Ollama verifier batch ${i + 1} failed (${err.message}) -- reporting unverified`);
        allFindings.push(...candidates);
      }
    }

    emit(`Ollama pass finished: ${allFindings.length} finding(s)`);
    return { findings: allFindings, batchCount: batches.length, partial };
  }
}

module.exports = { OllamaAuditor, DEFAULT_MODEL, DEFAULT_BASE_URL };
