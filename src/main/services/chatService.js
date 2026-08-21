const fs = require('fs');
const path = require('path');
const Anthropic = require('@anthropic-ai/sdk');
const Groq = require('groq-sdk');
const OpenAI = require('openai');
const { BASE_URL: DEEPSEEK_BASE_URL, DEFAULT_MODEL: DEEPSEEK_DEFAULT_MODEL } = require('./deepseekAuditor');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const { FINDING_CHAT_SYSTEM_PROMPT } = require('../constants/systemPrompt');

const CHAT_TEMPERATURE = 0.3;
const CHAT_MAX_TOKENS = 1024;
const CONTEXT_LINES_AROUND = 25;

// Reads a bounded window of source around the finding's line rather than the
// whole file -- plenty of context for a follow-up question, without risking
// a huge file blowing the request budget on every message in the thread.
function readFindingContext(rootDir, finding) {
  try {
    const absolutePath = path.join(rootDir, finding.file);
    const content = fs.readFileSync(absolutePath, 'utf8');
    const lines = content.split('\n');
    const start = Math.max(0, (finding.line || 1) - 1 - CONTEXT_LINES_AROUND);
    const end = Math.min(lines.length, (finding.lineEnd || finding.line || 1) + CONTEXT_LINES_AROUND);
    return lines
      .slice(start, end)
      .map((line, i) => `${start + i + 1}| ${line}`)
      .join('\n');
  } catch (err) {
    return `(could not read ${finding.file}: ${err.message})`;
  }
}

function buildFindingContent(rootDir, finding) {
  const context = readFindingContext(rootDir, finding);
  return `Finding under discussion:
- severity: ${finding.severity}
- title: ${finding.title}
- file: ${finding.file}:${finding.line}
- description: ${finding.description}
${finding.verifierReason ? `- verifier note: ${finding.verifierReason}\n` : ''}
Source around the finding (${finding.file}):
${context}`;
}

// history: array of { role: 'user' | 'assistant', content: string }, oldest first.
// question: the new user message to answer.
async function chat({ provider, apiKey, model, ollamaBaseUrl, rootDir, finding, history, question }) {
  const findingContent = buildFindingContent(rootDir, finding);
  const firstTurn = !history || history.length === 0;
  // Only send the finding+code block once -- repeating it on every turn just
  // burns tokens for no benefit once it's already in the conversation.
  const userContent = firstTurn ? `${findingContent}\n\nQuestion: ${question}` : question;

  if (provider === 'mock') {
    return `[MOCK] This is a canned chat response for testing, not a real answer. You asked: "${question}" about "${finding.title}" at ${finding.file}:${finding.line}.`;
  }

  if (provider === 'claude') {
    const client = new Anthropic({ apiKey });
    const messages = [...(history || []), { role: 'user', content: userContent }];
    const response = await client.messages.create({
      model: model || 'claude-sonnet-5',
      max_tokens: CHAT_MAX_TOKENS,
      temperature: CHAT_TEMPERATURE,
      system: FINDING_CHAT_SYSTEM_PROMPT,
      messages,
    });
    const block = response.content.find((b) => b.type === 'text');
    return (block && block.text) || '';
  }

  if (provider === 'gemini') {
    const client = new GoogleGenerativeAI(apiKey);
    const genModel = client.getGenerativeModel({
      model: model || 'gemini-2.5-flash',
      systemInstruction: FINDING_CHAT_SYSTEM_PROMPT,
      generationConfig: { temperature: CHAT_TEMPERATURE, maxOutputTokens: CHAT_MAX_TOKENS },
    });
    // Gemini uses 'model' rather than 'assistant' for its own turns.
    const geminiHistory = (history || []).map((m) => ({
      role: m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: m.content }],
    }));
    const session = genModel.startChat({ history: geminiHistory });
    const result = await session.sendMessage(userContent);
    return result.response.text();
  }

  // groq / openai / deepseek / ollama all speak the OpenAI-compatible
  // chat.completions shape, so one branch covers them -- only the client
  // construction differs.
  let client;
  let defaultModel;
  if (provider === 'groq') {
    client = new Groq({ apiKey });
    // Was llama-3.3-70b-versatile, which now 404s -- Groq's catalog moved.
    defaultModel = 'openai/gpt-oss-120b';
  } else if (provider === 'deepseek') {
    client = new OpenAI({ apiKey, baseURL: DEEPSEEK_BASE_URL });
    defaultModel = DEEPSEEK_DEFAULT_MODEL;
  } else if (provider === 'openai') {
    client = new OpenAI({ apiKey });
    defaultModel = 'gpt-4.1-mini';
  } else if (provider === 'ollama') {
    client = new OpenAI({ apiKey: 'ollama', baseURL: ollamaBaseUrl });
    defaultModel = 'llama3.1';
  } else {
    throw new Error(`Unknown provider: ${provider}`);
  }

  const response = await client.chat.completions.create({
    model: model || defaultModel,
    max_tokens: CHAT_MAX_TOKENS,
    temperature: CHAT_TEMPERATURE,
    messages: [
      { role: 'system', content: FINDING_CHAT_SYSTEM_PROMPT },
      ...(history || []),
      { role: 'user', content: userContent },
    ],
  });
  return response.choices[0].message.content || '';
}

module.exports = { chat };
