const fs = require('fs');
const path = require('path');
const Anthropic = require('@anthropic-ai/sdk');
const Groq = require('groq-sdk');
const OpenAI = require('openai');
const { GoogleGenerativeAI } = require('@google/generative-ai');

// Lines of surrounding source shown on each side of the finding, so the
// advisor sees enough context to write a real fix without sending the
// whole file.
const CONTEXT_LINES = 15;
const FIX_TEMPERATURE = 0.2;

// A distinct role from the scanner/verifier prompts in systemPrompt.js --
// those are told never to propose fixes ("report only"). This one exists
// specifically because the user clicked "suggest fix" on an already-reported
// finding, so recommending one here doesn't violate that boundary: nothing
// is ever written back to disk, this is advisory text a human reads and
// applies (or doesn't) themselves.
const FIX_ADVISOR_SYSTEM_PROMPT = `You are a FIX ADVISOR. You are given one confirmed security finding and the surrounding source code. Recommend a concrete fix -- you do not modify anything yourself, and nothing you say is applied automatically; a human decides whether to use it.

Rules:
- Give a short explanation (2-4 sentences) of the fix and why it addresses the vulnerability.
- Then give a corrected code snippet covering the affected lines, in a fenced code block, in the same language as the source.
- Keep the fix minimal and scoped to this specific finding -- don't refactor unrelated code.
- If the fix needs a new dependency or a config/infra change outside this file, say so briefly instead of inventing code you can't see.`;

function extractSnippet(rootDir, finding) {
  const absPath = path.join(rootDir, finding.file);
  let content;
  try {
    content = fs.readFileSync(absPath, 'utf8');
  } catch {
    // e.g. an npm-audit finding anchored at package.json:1 with nothing
    // meaningful to show, or the file moved/was deleted since the scan.
    return null;
  }
  const lines = content.split('\n');
  const start = Math.max(0, finding.line - 1 - CONTEXT_LINES);
  const end = Math.min(lines.length, (finding.lineEnd || finding.line) + CONTEXT_LINES);
  return lines.slice(start, end).map((line, i) => `${start + i + 1}| ${line}`).join('\n');
}

function buildUserContent(finding, snippet) {
  const findingText = `Finding: ${finding.title}\nSeverity: ${finding.severity}\nLocation: ${finding.file}:${finding.line}\nDescription: ${finding.description || ''}`;
  return snippet
    ? `${findingText}\n\nSurrounding source (line-numbered):\n${snippet}`
    : `${findingText}\n\n(Source file not available for this finding -- it may be a dependency-level finding with no single code location.)`;
}

async function suggestFix({ provider, apiKey, model, ollamaBaseUrl, rootDir, finding }) {
  if (provider === 'mock') {
    return {
      fix: `[mock] Suggested fix for "${finding.title}":\n\nThis is a canned response -- switch to a real provider in Settings to get an actual AI-generated fix.\n\n\`\`\`\n// example: validate/escape input before it reaches the sink at ${finding.file}:${finding.line}\n\`\`\``,
    };
  }

  const snippet = extractSnippet(rootDir, finding);
  const userContent = buildUserContent(finding, snippet);

  if (provider === 'claude') {
    const client = new Anthropic({ apiKey });
    const response = await client.messages.create({
      model: model || 'claude-sonnet-5',
      max_tokens: 1024,
      temperature: FIX_TEMPERATURE,
      system: FIX_ADVISOR_SYSTEM_PROMPT,
      messages: [{ role: 'user', content: userContent }],
    });
    const text = response.content.filter((b) => b.type === 'text').map((b) => b.text).join('\n');
    return { fix: text };
  }

  if (provider === 'groq') {
    const client = new Groq({ apiKey });
    const response = await client.chat.completions.create({
      model: model || 'llama-3.3-70b-versatile',
      temperature: FIX_TEMPERATURE,
      max_tokens: 1024,
      messages: [
        { role: 'system', content: FIX_ADVISOR_SYSTEM_PROMPT },
        { role: 'user', content: userContent },
      ],
    });
    return { fix: response.choices[0].message.content };
  }

  if (provider === 'gemini') {
    const client = new GoogleGenerativeAI(apiKey);
    const genModel = client.getGenerativeModel({
      model: model || 'gemini-2.5-flash',
      systemInstruction: FIX_ADVISOR_SYSTEM_PROMPT,
    });
    const result = await genModel.generateContent({
      contents: [{ role: 'user', parts: [{ text: userContent }] }],
      generationConfig: { temperature: FIX_TEMPERATURE, maxOutputTokens: 1024 },
    });
    return { fix: result.response.text() };
  }

  if (provider === 'openai') {
    const client = new OpenAI({ apiKey });
    const response = await client.chat.completions.create({
      model: model || 'gpt-4.1-mini',
      temperature: FIX_TEMPERATURE,
      max_tokens: 1024,
      messages: [
        { role: 'system', content: FIX_ADVISOR_SYSTEM_PROMPT },
        { role: 'user', content: userContent },
      ],
    });
    return { fix: response.choices[0].message.content };
  }

  if (provider === 'ollama') {
    const client = new OpenAI({ apiKey: 'ollama', baseURL: ollamaBaseUrl });
    const response = await client.chat.completions.create({
      model: model || 'llama3.1',
      temperature: FIX_TEMPERATURE,
      messages: [
        { role: 'system', content: FIX_ADVISOR_SYSTEM_PROMPT },
        { role: 'user', content: userContent },
      ],
    });
    return { fix: response.choices[0].message.content };
  }

  throw new Error(`Unknown provider: ${provider}`);
}

module.exports = { suggestFix };
