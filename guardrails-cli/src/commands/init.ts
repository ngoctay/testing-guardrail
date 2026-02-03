import chalk from "chalk";
import ora from "ora";
import fs from "fs/promises";
import path from "path";
import { getGitRoot, isGitRepo } from "../services/git.js";

interface InitOptions {
  force?: boolean;
}

/**
 * Validates that a file path is safe and doesn't traverse outside the base directory.
 * Prevents path traversal attacks (CWE-22).
 */
function isPathSafe(basePath: string, targetPath: string): boolean {
  const normalizedBase = path.resolve(basePath);
  const normalizedTarget = path.resolve(targetPath);
  return normalizedTarget.startsWith(normalizedBase + path.sep) ||
         normalizedTarget === normalizedBase;
}

const DEFAULT_CONFIG = `# Guardrails Configuration
enforcement_mode: warning  # advisory | warning | blocking

rule_packs:
  - default-security
  - enterprise-standards

security:
  block_threshold: high
  secrets: { enabled: true }
  sql_injection: { enabled: true }

standards:
  naming: { enabled: true }
  logging: { enabled: true, forbid_console_log: true }
  error_handling: { enabled: true, forbid_empty_catch: true }

license:
  allowed: [MIT, Apache-2.0, BSD-3-Clause]
  blocked: [GPL-3.0, AGPL-3.0]

copilot:
  strict_mode: true
`;

const PRE_COMMIT_HOOK = `#!/bin/sh
# Guardrails pre-commit hook

# Run guardrails scan
npx guardrails scan

# Capture the exit code
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  echo ""
  echo "Commit blocked by guardrails. Fix the issues above or use --no-verify to skip."
  exit 1
fi

exit 0
`;

export async function initCommand(options: InitOptions): Promise<void> {
  console.log(chalk.bold("Initializing Guardrails...\n"));

  // Check if we're in a git repository
  if (!(await isGitRepo())) {
    console.error(chalk.red("Error: Not a git repository"));
    console.log(chalk.dim("Run this command from the root of a git repository"));
    process.exit(1);
  }

  const gitRoot = await getGitRoot();

  // Create .github directory if it doesn't exist
  // Using normalized paths to prevent path traversal
  const githubDir = path.normalize(path.join(gitRoot, ".github"));
  const configPath = path.normalize(path.join(githubDir, "guardrails.yaml"));

  // Validate paths are within git root
  if (!isPathSafe(gitRoot, githubDir) || !isPathSafe(gitRoot, configPath)) {
    console.error(chalk.red("Error: Invalid path detected"));
    process.exit(1);
  }

  // Check if config already exists
  const configExists = await fileExists(configPath);
  if (configExists && !options.force) {
    console.log(chalk.yellow("Configuration already exists at .github/guardrails.yaml"));
    console.log(chalk.dim("Use --force to overwrite"));
  } else {
    const spinner = ora("Creating configuration file...").start();
    try {
      await fs.mkdir(githubDir, { recursive: true });
      await fs.writeFile(configPath, DEFAULT_CONFIG, "utf-8");
      spinner.succeed("Created .github/guardrails.yaml");
    } catch (error) {
      spinner.fail("Failed to create configuration file");
      console.error(error);
      process.exit(1);
    }
  }

  // Install pre-commit hook
  // Using normalized paths to prevent path traversal
  const hooksDir = path.normalize(path.join(gitRoot, ".git", "hooks"));
  const preCommitPath = path.normalize(path.join(hooksDir, "pre-commit"));

  // Validate paths are within git root
  if (!isPathSafe(gitRoot, hooksDir) || !isPathSafe(gitRoot, preCommitPath)) {
    console.error(chalk.red("Error: Invalid hooks path detected"));
    process.exit(1);
  }

  const hookExists = await fileExists(preCommitPath);
  if (hookExists && !options.force) {
    console.log(chalk.yellow("Pre-commit hook already exists"));
    console.log(chalk.dim("Use --force to overwrite"));
  } else {
    const spinner = ora("Installing pre-commit hook...").start();
    try {
      await fs.mkdir(hooksDir, { recursive: true });
      await fs.writeFile(preCommitPath, PRE_COMMIT_HOOK, { mode: 0o755 });
      spinner.succeed("Installed pre-commit hook");
    } catch (error) {
      spinner.fail("Failed to install pre-commit hook");
      console.error(error);
      process.exit(1);
    }
  }

  console.log();
  console.log(chalk.green.bold("✓ Guardrails initialized successfully!"));
  console.log();
  console.log("Next steps:");
  console.log(chalk.dim("1. Review and customize .github/guardrails.yaml"));
  console.log(chalk.dim("2. Set BACKEND_API_URL environment variable (optional)"));
  console.log(chalk.dim("3. Stage some changes and commit to test"));
  console.log();
  console.log(chalk.dim("Run 'guardrails scan' to scan files manually"));
}

async function fileExists(filePath: string): Promise<boolean> {
  try {
    // Normalize path before checking
    const normalizedPath = path.normalize(filePath);
    await fs.access(normalizedPath);
    return true;
  } catch {
    return false;
  }
}
