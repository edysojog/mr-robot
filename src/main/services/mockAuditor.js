const crypto = require('crypto');

function makeId(parts) {
  return crypto.createHash('sha1').update(parts.join('|')).digest('hex').slice(0, 16);
}

// Stand-in for AnthropicAuditor with the same review(files, semgrepFindings,
// onProgress) interface, so scanHandlers.js can swap it in without special-casing
// the orchestration. Returns deterministic canned findings -- no API call, no cost.
// One finding intentionally lands on the same file+line as a real Semgrep match
// (see mrrobot-test-target/app.py's shell=True call) so the merge/"confirmed by
// both" path can be exercised too.
class MockAuditor {
  constructor(verify = true, recon = true) {
    this.verify = verify;
    this.recon = recon;
  }

  async review(files, semgrepFindings, onProgress) {
    const emit = (msg) => { if (onProgress) onProgress(msg); };

    if (this.recon && files.length > 0) {
      emit('[mock] recon: mapping codebase attack surface…');
      await new Promise((resolve) => setTimeout(resolve, 300));
      emit(`[mock] recon finished: ${Math.min(files.length, 3)} priority file(s) identified`);
    }

    emit(`[mock] reviewing ${files.length} file(s) (no API call, no cost)`);
    await new Promise((resolve) => setTimeout(resolve, 400)); // simulate latency for a realistic progress log
    emit('[mock] scanner batch 1/1…');
    await new Promise((resolve) => setTimeout(resolve, 400));

    const candidates = [];

    const semgrepHit = semgrepFindings[0];
    if (semgrepHit) {
      candidates.push({
        id: makeId(['mock-claude', semgrepHit.file, String(semgrepHit.line), 'confirm']),
        source: 'claude',
        severity: semgrepHit.severity,
        title: `${semgrepHit.title} (mock confirmation)`,
        description: `[MOCK] Corroborates the Semgrep finding at ${semgrepHit.file}:${semgrepHit.line} -- this is canned output for testing the merge path, not a real model response.`,
        file: semgrepHit.file,
        line: semgrepHit.line,
        lineEnd: semgrepHit.line,
        confidence: 'high',
      });
    }

    if (files.length > 0) {
      const first = files[0];
      candidates.push({
        id: makeId(['mock-claude', first.relativePath, '1', 'architectural']),
        source: 'claude',
        severity: 'medium',
        title: 'Mock architectural finding',
        description: '[MOCK] Canned example of a logic-level finding a static scanner would miss -- for testing only, not a real analysis result.',
        file: first.relativePath,
        line: 1,
        lineEnd: 1,
        confidence: 'medium',
      });
    }

    if (!this.verify || candidates.length === 0) {
      emit(`[mock] pass finished: ${candidates.length} finding(s)`);
      return { findings: candidates, batchCount: 1, partial: false };
    }

    emit(`[mock] verifier batch 1/1: checking ${candidates.length} candidate(s)…`);
    await new Promise((resolve) => setTimeout(resolve, 300));

    // Canned verdicts, so the "verified" badge / dropped-finding path can be
    // exercised in the UI without a real API call: the first candidate is
    // confirmed as-is, and (if present) the second is confirmed but
    // downgraded -- neither is rejected, so the mock pass never reports zero.
    const findings = candidates.map((f, i) => {
      if (i === 1) {
        return { ...f, severity: 'low', confidence: 'low', verified: true, verifierReason: '[MOCK] Downgraded -- canned example of a verifier softening an overstated finding.' };
      }
      return { ...f, verified: true, verifierReason: '[MOCK] Confirmed -- canned verifier output for testing, not a real review.' };
    });

    emit(`[mock] verifier batch 1/1: ${findings.length}/${candidates.length} confirmed`);
    emit(`[mock] pass finished: ${findings.length} finding(s)`);
    return { findings, batchCount: 1, partial: false };
  }
}

module.exports = { MockAuditor };
