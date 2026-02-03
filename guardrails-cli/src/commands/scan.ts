import chalk from "chalk";
import ora from "ora";
import { getStagedFiles, getFileContent } from "../services/git.js";
import { scanCode, ScanResult } from "../services/api-client.js";
import { loadConfig } from "../services/config.js";
import { formatResults, formatResultsJson } from "../services/formatter.js";

interface ScanOptions {
  all?: boolean;
  ai?: boolean;
  verbose?: boolean;
  json?: boolean;
  fix?: boolean;
}

export async function scanCommand(options: ScanOptions): Promise<void> {
  const config = await loadConfig();
  const enableAi = options.ai !== false;

  // Get files to scan
  const spinner = ora("Getting files to scan...").start();

  let files: string[];
  try {
    if (options.all) {
      // For --all, we'd need to implement a different file listing
      // For now, just use staged files
      files = await getStagedFiles();
    } else {
      files = await getStagedFiles();
    }
  } catch (error) {
    spinner.fail("Failed to get files");
    console.error(chalk.red(error instanceof Error ? error.message : "Unknown error"));
    process.exit(1);
  }

  if (files.length === 0) {
    spinner.info("No files to scan");
    process.exit(0);
  }

  spinner.succeed(`Found ${files.length} file(s) to scan`);

  // Filter to supported file types
  const supportedExtensions = [
    ".ts", ".tsx", ".js", ".jsx", ".py", ".java",
    ".go", ".rb", ".rs", ".cpp", ".c", ".cs", ".php"
  ];

  const supportedFiles = files.filter((file) =>
    supportedExtensions.some((ext) => file.endsWith(ext))
  );

  if (supportedFiles.length === 0) {
    console.log(chalk.yellow("No supported files found in staged changes"));
    process.exit(0);
  }

  console.log(chalk.dim(`Scanning ${supportedFiles.length} supported file(s)...`));
  console.log();

  // Scan each file
  const allResults: ScanResult[] = [];
  let hasErrors = false;
  let hasCritical = false;

  for (const file of supportedFiles) {
    const fileSpinner = ora(`Scanning ${file}...`).start();

    try {
      const content = await getFileContent(file);
      if (!content) {
        fileSpinner.warn(`Skipped ${file} (empty or unreadable)`);
        continue;
      }

      const language = getLanguageFromFile(file);
      const result = await scanCode({
        code: content,
        filePath: file,
        language,
        enableAi,
        enforcementMode: config.enforcementMode,
        rulePacks: config.rulePacks,
      });

      allResults.push(result);

      if (result.summary.totalIssues === 0) {
        fileSpinner.succeed(chalk.green(`${file} - No issues`));
      } else {
        const criticalHigh = result.summary.critical + result.summary.high;
        if (criticalHigh > 0) {
          hasCritical = true;
          fileSpinner.fail(
            chalk.red(`${file} - ${result.summary.totalIssues} issue(s) (${criticalHigh} critical/high)`)
          );
        } else {
          fileSpinner.warn(
            chalk.yellow(`${file} - ${result.summary.totalIssues} issue(s)`)
          );
        }
        hasErrors = true;
      }
    } catch (error) {
      fileSpinner.fail(chalk.red(`Error scanning ${file}`));
      if (options.verbose) {
        console.error(error);
      }
    }
  }

  console.log();

  // Output results
  if (options.json) {
    console.log(formatResultsJson(allResults));
  } else {
    console.log(formatResults(allResults, options.verbose || false));
  }

  // Summary
  console.log();
  const totalIssues = allResults.reduce(
    (sum, r) => sum + r.summary.totalIssues,
    0
  );
  const totalCritical = allResults.reduce(
    (sum, r) => sum + r.summary.critical,
    0
  );
  const totalHigh = allResults.reduce((sum, r) => sum + r.summary.high, 0);

  if (totalIssues === 0) {
    console.log(chalk.green.bold("✓ All checks passed!"));
    process.exit(0);
  }

  console.log(
    chalk.bold(
      `Found ${totalIssues} issue(s): ` +
        chalk.red(`${totalCritical} critical`) +
        ", " +
        chalk.yellow(`${totalHigh} high`)
    )
  );

  // Determine exit code based on enforcement mode
  if (config.enforcementMode === "blocking" && hasCritical) {
    console.log();
    console.log(
      chalk.red.bold("✗ Commit blocked due to critical/high severity issues")
    );
    console.log(chalk.dim("Fix the issues above or use --no-verify to skip"));
    process.exit(1);
  } else if (config.enforcementMode === "warning" && hasErrors) {
    console.log();
    console.log(
      chalk.yellow.bold("⚠ Warning: Issues found but commit allowed")
    );
    process.exit(0);
  } else {
    process.exit(0);
  }
}

function getLanguageFromFile(filename: string): string {
  const ext = filename.split(".").pop()?.toLowerCase() || "";
  const langMap: Record<string, string> = {
    ts: "typescript",
    tsx: "typescript",
    js: "javascript",
    jsx: "javascript",
    py: "python",
    java: "java",
    go: "go",
    rb: "ruby",
    rs: "rust",
    cpp: "cpp",
    c: "c",
    cs: "csharp",
    php: "php",
  };
  return langMap[ext] || ext;
}
