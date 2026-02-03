import { exec } from "child_process";
import { promisify } from "util";
import fs from "fs/promises";
import path from "path";

const execAsync = promisify(exec);

/**
 * Validates that a file path is safe and doesn't traverse outside the base directory.
 * Prevents path traversal attacks (CWE-22).
 */
function isPathSafe(basePath: string, targetPath: string): boolean {
  const normalizedBase = path.resolve(basePath);
  const normalizedTarget = path.resolve(basePath, targetPath);
  return normalizedTarget.startsWith(normalizedBase + path.sep) ||
         normalizedTarget === normalizedBase;
}

export async function isGitRepo(): Promise<boolean> {
  try {
    await execAsync("git rev-parse --git-dir");
    return true;
  } catch {
    return false;
  }
}

export async function getGitRoot(): Promise<string> {
  const { stdout } = await execAsync("git rev-parse --show-toplevel");
  return stdout.trim();
}

export async function getStagedFiles(): Promise<string[]> {
  try {
    const { stdout } = await execAsync("git diff --cached --name-only --diff-filter=ACM");
    if (!stdout.trim()) {
      return [];
    }
    return stdout
      .trim()
      .split("\n")
      .filter((file) => file.length > 0);
  } catch {
    return [];
  }
}

export async function getFileContent(filePath: string): Promise<string | null> {
  // Validate path to prevent path traversal attacks
  if (filePath.includes("..") || path.isAbsolute(filePath)) {
    console.error("Invalid file path: path traversal not allowed");
    return null;
  }

  try {
    // First try to get the staged version
    const { stdout } = await execAsync(`git show :${filePath}`);
    return stdout;
  } catch {
    // Fall back to file system
    try {
      const gitRoot = await getGitRoot();

      // Additional safety check: ensure path stays within git root
      if (!isPathSafe(gitRoot, filePath)) {
        console.error("Invalid file path: outside repository root");
        return null;
      }

      const fullPath = path.normalize(path.join(gitRoot, filePath));
      return await fs.readFile(fullPath, "utf-8");
    } catch {
      return null;
    }
  }
}

export async function getAllFiles(): Promise<string[]> {
  try {
    const { stdout } = await execAsync("git ls-files");
    return stdout
      .trim()
      .split("\n")
      .filter((file) => file.length > 0);
  } catch {
    return [];
  }
}
