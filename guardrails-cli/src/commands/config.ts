import chalk from "chalk";
import { loadConfig, saveConfig, GuardrailsConfig } from "../services/config.js";
import YAML from "yaml";

interface ConfigOptions {
  show?: boolean;
  set?: string;
}

export async function configCommand(options: ConfigOptions): Promise<void> {
  if (options.show || (!options.show && !options.set)) {
    await showConfig();
    return;
  }

  if (options.set) {
    await setConfig(options.set);
    return;
  }
}

async function showConfig(): Promise<void> {
  try {
    const config = await loadConfig();
    console.log(chalk.bold("Current Configuration:\n"));
    console.log(YAML.stringify(config));
  } catch (error) {
    console.error(chalk.red("Failed to load configuration"));
    console.log(chalk.dim("Run 'guardrails init' to create a configuration file"));
    process.exit(1);
  }
}

// Dangerous keys that could lead to prototype pollution
const FORBIDDEN_KEYS = ["__proto__", "constructor", "prototype"];

function isSafeKey(key: string): boolean {
  return !FORBIDDEN_KEYS.includes(key.toLowerCase());
}

async function setConfig(keyValue: string): Promise<void> {
  const [key, value] = keyValue.split("=");

  if (!key || value === undefined) {
    console.error(chalk.red("Invalid format. Use: guardrails config --set key=value"));
    process.exit(1);
  }

  try {
    const config = await loadConfig();

    // Handle nested keys (e.g., security.block_threshold)
    const keys = key.split(".");

    // Validate all keys against prototype pollution
    for (const k of keys) {
      if (!isSafeKey(k)) {
        console.error(chalk.red(`Invalid key: "${k}" is not allowed`));
        process.exit(1);
      }
    }

    let current: Record<string, unknown> = config as Record<string, unknown>;

    for (let i = 0; i < keys.length - 1; i++) {
      const currentKey = keys[i];
      if (!Object.prototype.hasOwnProperty.call(current, currentKey)) {
        current[currentKey] = {};
      }
      current = current[currentKey] as Record<string, unknown>;
    }

    // Parse value
    let parsedValue: unknown = value;
    if (value === "true") parsedValue = true;
    else if (value === "false") parsedValue = false;
    else if (!isNaN(Number(value))) parsedValue = Number(value);
    else if (value.startsWith("[") && value.endsWith("]")) {
      parsedValue = value
        .slice(1, -1)
        .split(",")
        .map((v) => v.trim());
    }

    const finalKey = keys[keys.length - 1];
    current[finalKey] = parsedValue;

    await saveConfig(config as GuardrailsConfig);
    console.log(chalk.green(`✓ Set ${key} = ${value}`));
  } catch (error) {
    console.error(chalk.red("Failed to update configuration"));
    console.error(error);
    process.exit(1);
  }
}
