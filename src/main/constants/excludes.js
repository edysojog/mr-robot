const EXCLUDED_DIR_NAMES = new Set([
  'node_modules', '.git', '.hg', '.svn', 'dist', 'build', 'out',
  '.next', '.nuxt', 'target', 'vendor', 'venv', '.venv', '__pycache__',
  '.cache', 'coverage', '.idea', '.vscode', 'release',
]);

const INCLUDED_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.py', '.go', '.java', '.rb', '.php', '.cs', '.cpp', '.c', '.h', '.hpp',
  '.rs', '.kt', '.swift', '.scala',
  '.html', '.htm', '.yml', '.yaml', '.json', '.sql', '.sh', '.ps1',
]);

const EXCLUDED_FILE_PATTERNS = [
  /\.min\.js$/i,
  /package-lock\.json$/i,
  /yarn\.lock$/i,
  /pnpm-lock\.yaml$/i,
];

const MAX_FILES_WARN = 20000;
const MAX_FILE_BYTES_FOR_LLM = 500 * 1024; // 500KB
const MAX_TOTAL_LLM_BYTES = 20 * 1024 * 1024; // 20MB aggregate budget

module.exports = {
  EXCLUDED_DIR_NAMES,
  INCLUDED_EXTENSIONS,
  EXCLUDED_FILE_PATTERNS,
  MAX_FILES_WARN,
  MAX_FILE_BYTES_FOR_LLM,
  MAX_TOTAL_LLM_BYTES,
};
