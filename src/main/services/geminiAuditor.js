const { GoogleGenerativeAI } = require('@google/generative-ai');
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

const DEFAULT_MODEL = 'gemini-2.5-flash';

// Gemini's REST/SDK naming differs from Claude/Groq (tool_use vs OpenAI-style
// function calling) but the underlying JSON-schema `parameters` object is
// compatible as-is with REPORT_FINDINGS_SCHEMA etc. -- no translation needed.
class GeminiAuditor {
  constructor(apiKey, model, verify = true, recon = true) {
    this.client = new GoogleGenerativeAI(apiKey);
    this.model = model || DEFAULT_MODEL;
    this.verify = verify;
    this.recon = recon;
  }

  // Shared single-tool-call helper -- recon/scanner/verifier only differ in
  // system prompt, tool schema, and input, so this avoids repeating the
  // generateContent/functionCalls plumbing three times.
  async callTool(systemPrompt, userContent, toolName, toolDescription, schema, maxOutputTokens) {
    const genModel = this.client.getGenerativeModel({
      model: this.model,
      systemInstruction: systemPrompt,
      tools: [{ functionDeclarations: [{ name: toolName, description: toolDescription, parameters: schema }] }],
      toolConfig: { functionCallingConfig: { mode: 'ANY', allowedFunctionNames: [toolName] } },
      generationConfig: { temperature: AUDITOR_TEMPERATURE, maxOutputTokens },
    });

    const result = await genModel.generateContent(userContent);
    const call = result.response.functionCalls()?.[0];
    return call ? call.args : null;
  }

  async runRecon(files, emit) {
    if (!this.recon || files.length === 0) return { summary: null, priorityFiles: [] };

    emit('Gemini recon: mapping codebase attack surface…');
    try {
      const args = await this.callTool(
        RECON_SYSTEM_PROMPT,
        buildReconUserContent(files),
        'report_recon',
        'Report the codebase summary and priority files for the scanner stage.',
        RECON_SCHEMA,
        1024
      );
      const summary = (args && args.summary) || null;
      const priorityFiles = (args && args.priorityFiles) || [];
      emit(`Gemini recon finished: ${priorityFiles.length} priority file(s) identified`);
      return { summary, priorityFiles };
    } catch (err) {
      emit(`Gemini recon failed (${err.message}) -- continuing without it`);
      return { summary: null, priorityFiles: [] };
    }
  }

  async review(files, semgrepFindings, onProgress) {
    const emit = (msg) => { if (onProgress) onProgress(msg); };

    const { summary: reconSummary, priorityFiles } = await this.runRecon(files, emit);
    const priorityContext = [...semgrepFindings, ...reconPriorityAsFindings(priorityFiles)];

    const selected = prioritizeFiles(files, priorityContext);
    if (selected.length === 0) {
      emit('no files eligible for the Gemini pass');
      return { findings: [], batchCount: 0, partial: false };
    }

    const fileTexts = selected.map((f) => ({ file: f, text: readFileForPrompt(f) }));
    const batches = batchByTokens(fileTexts);
    const partial = batches.length < estimateTotalBatches(fileTexts);

    emit(`sending ${selected.length} file(s) to Gemini in ${batches.length} batch(es)`);

    const allFindings = [];

    for (let i = 0; i < batches.length; i += 1) {
      emit(`Gemini scanner batch ${i + 1}/${batches.length}…`);
      const userContent = buildBatchUserContent(batches[i], semgrepFindings, reconSummary);

      let candidates = [];
      try {
        const args = await this.callTool(
          SCANNER_SYSTEM_PROMPT,
          userContent,
          'report_findings',
          'Report the security findings identified in this batch of files.',
          REPORT_FINDINGS_SCHEMA,
          4096
        );
        const findings = (args && args.findings) || [];
        candidates = findings.map((f) => toFinding('claude', f));
      } catch (err) {
        emit(`Gemini scanner batch ${i + 1} failed: ${err.message}`);
        continue;
      }

      if (!this.verify || candidates.length === 0) {
        allFindings.push(...candidates);
        continue;
      }

      emit(`Gemini verifier batch ${i + 1}/${batches.length}: checking ${candidates.length} candidate(s)…`);
      try {
        const verifyContent = buildVerificationUserContent(batches[i], candidates);
        const args = await this.callTool(
          VERIFIER_SYSTEM_PROMPT,
          verifyContent,
          'verify_findings',
          'Report a confirm/reject verdict for every candidate finding.',
          VERIFY_FINDINGS_SCHEMA,
          4096
        );
        const verdicts = (args && args.verdicts) || [];
        const confirmed = applyVerdicts(candidates, verdicts);
        emit(`Gemini verifier batch ${i + 1}/${batches.length}: ${confirmed.length}/${candidates.length} confirmed`);
        allFindings.push(...confirmed);
      } catch (err) {
        emit(`Gemini verifier batch ${i + 1} failed (${err.message}) -- reporting unverified`);
        allFindings.push(...candidates);
      }
    }

    emit(`Gemini pass finished: ${allFindings.length} finding(s)`);
    return { findings: allFindings, batchCount: batches.length, partial };
  }
}

module.exports = { GeminiAuditor, DEFAULT_MODEL };
