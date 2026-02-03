import { Command } from "commander";
import { scanCommand } from "./commands/scan.js";
import { initCommand } from "./commands/init.js";
import { configCommand } from "./commands/config.js";

const program = new Command();

program
  .name("guardrails")
  .description("AI Powered Enterprise Guardrails for GitHub Copilot")
  .version("1.0.0");

// Scan command
program
  .command("scan")
  .description("Scan staged files for security and standards violations")
  .option("-a, --all", "Scan all files, not just staged")
  .option("--no-ai", "Disable AI analysis")
  .option("-v, --verbose", "Verbose output")
  .option("--json", "Output results as JSON")
  .option("--fix", "Attempt to auto-fix issues")
  .action(scanCommand);

// Init command
program
  .command("init")
  .description("Initialize guardrails configuration and pre-commit hook")
  .option("--force", "Overwrite existing configuration")
  .action(initCommand);

// Config command
program
  .command("config")
  .description("View or modify configuration")
  .option("--show", "Show current configuration")
  .option("--set <key=value>", "Set a configuration value")
  .action(configCommand);

program.parse();
