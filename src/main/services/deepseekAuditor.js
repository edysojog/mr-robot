const OpenAI = require('openai');
const { OpenAIAuditor } = require('./openaiAuditor');

// DeepSeek serves an OpenAI-compatible chat-completions API, so the entire
// Recon -> Scanner -> Verifier implementation in OpenAIAuditor applies
// unchanged; only the client's base URL and the default model differ. That
// makes this a constructor override rather than a fourth near-copy of the
// same 170 lines (openaiAuditor/ollamaAuditor are already two).
//
// The one thing worth checking before trusting the reuse: every auditor here
// pins `tool_choice: { type: 'function', function: { name: ... } }` -- forced,
// not "auto" -- and OpenAI-compatible endpoints vary in whether they honor
// that. DeepSeek's chat-completions reference documents the object form as
// forcing the named tool, alongside none/auto/required, so the forced shape
// this codebase depends on is supported.
const BASE_URL = 'https://api.deepseek.com';

// Best-effort as of this writing rather than guaranteed current -- the same
// stance the other non-Claude providers take here, which is why the model is
// a free-text override everywhere instead of a fixed dropdown. deepseek-v4-pro
// is the heavier sibling if recall matters more than cost.
const DEFAULT_MODEL = 'deepseek-v4-flash';

class DeepseekAuditor extends OpenAIAuditor {
  constructor(apiKey, model, verify = true, recon = true) {
    super(apiKey, model, verify, recon);
    this.client = new OpenAI({ apiKey, baseURL: BASE_URL });
    this.model = model || DEFAULT_MODEL;
    this.label = 'DeepSeek';
  }
}

module.exports = { DeepseekAuditor, DEFAULT_MODEL, BASE_URL };
