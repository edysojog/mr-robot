const fs = require('fs');
const path = require('path');
const {
  EXCLUDED_DIR_NAMES,
  INCLUDED_EXTENSIONS,
  EXCLUDED_FILE_PATTERNS,
  MAX_FILES_WARN,
} = require('../constants/excludes');

function isExcludedFile(name) {
  return EXCLUDED_FILE_PATTERNS.some((re) => re.test(name));
}

// Walks rootDir, returning an inventory of source files plus counts/guardrail flags.
// Does not read file contents -- that happens later, only for files actually sent to Claude.
async function walk(rootDir) {
  const files = [];
  const visitedRealPaths = new Set();
  let scannedCount = 0;
  let truncated = false;

  async function visit(dir) {
    if (truncated) return;

    let realPath;
    try {
      realPath = await fs.promises.realpath(dir);
    } catch {
      return; // broken symlink / permission error -- skip
    }
    if (visitedRealPaths.has(realPath)) return; // symlink loop guard
    visitedRealPaths.add(realPath);

    let entries;
    try {
      entries = await fs.promises.readdir(dir, { withFileTypes: true });
    } catch {
      return; // permission error -- skip this dir
    }

    for (const entry of entries) {
      if (truncated) return;
      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (EXCLUDED_DIR_NAMES.has(entry.name)) continue;
        await visit(fullPath);
      } else if (entry.isFile()) {
        if (isExcludedFile(entry.name)) continue;
        const ext = path.extname(entry.name).toLowerCase();
        if (!INCLUDED_EXTENSIONS.has(ext)) continue;

        scannedCount += 1;
        if (scannedCount > MAX_FILES_WARN) {
          truncated = true;
          return;
        }

        let size = 0;
        try {
          size = (await fs.promises.stat(fullPath)).size;
        } catch {
          continue;
        }

        files.push({
          absolutePath: fullPath,
          relativePath: path.relative(rootDir, fullPath).split(path.sep).join('/'),
          size,
        });
      }
    }
  }

  await visit(rootDir);

  return {
    rootDir,
    files,
    fileCount: files.length,
    totalBytes: files.reduce((sum, f) => sum + f.size, 0),
    truncated,
  };
}

// Builds the same {absolutePath, relativePath, size} shape as walk(), but
// from an explicit list of rootDir-relative paths (diff mode) instead of a
// full directory traversal. Applies the same extension/exclusion filters.
async function filesFromList(rootDir, relativePaths) {
  const files = [];

  for (const relPath of relativePaths) {
    const name = path.basename(relPath);
    if (isExcludedFile(name)) continue;
    const ext = path.extname(name).toLowerCase();
    if (!INCLUDED_EXTENSIONS.has(ext)) continue;

    const absolutePath = path.join(rootDir, relPath);
    let size = 0;
    try {
      size = (await fs.promises.stat(absolutePath)).size;
    } catch {
      continue;
    }

    files.push({ absolutePath, relativePath: relPath, size });
  }

  return files;
}

module.exports = { walk, filesFromList };
