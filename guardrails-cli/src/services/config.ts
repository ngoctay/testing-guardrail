import fs from "fs/promises";
import path from "path";
import YAML from "yaml";
import { getGitRoot } from "./git.js";

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

export interface GuardrailsConfig {
  enforcementMode: "advisory" | "warning" | "blocking";
  rulePacks: string[];
  security?: {
    blockThreshold?: string;
    secrets?: { enabled: boolean };
    sqlInjection?: { enabled: boolean };
  };
  standards?: {
    naming?: { enabled: boolean };
    logging?: { enabled: boolean; forbidConsoleLog?: boolean };
    errorHandling?: { enabled: boolean; forbidEmptyCatch?: boolean };
  };
  license?: {
    allowed?: string[];
    blocked?: string[];
  };
  copilot?: {
    strictMode?: boolean;
  };
}

const DEFAULT_CONFIG: GuardrailsConfig = {
  enforcementMode: "warning",
  rulePacks: ["default-security", "enterprise-standards"],
  security: {
    blockThreshold: "high",
    secrets: { enabled: true },
    sqlInjection: { enabled: true },
  },
  standards: {
    naming: { enabled: true },
    logging: { enabled: true, forbidConsoleLog: true },
    errorHandling: { enabled: true, forbidEmptyCatch: true },
  },
  license: {
    allowed: ["MIT", "Apache-2.0", "BSD-3-Clause"],
    blocked: ["GPL-3.0", "AGPL-3.0"],
  },
  copilot: {
    strictMode: true,
  },
};

export async function loadConfig(): Promise<GuardrailsConfig> {
  try {
    const gitRoot = await getGitRoot();
    // Use normalized path and validate it stays within git root
    const configPath = path.normalize(path.join(gitRoot, ".github", "guardrails.yaml"));

    if (!isPathSafe(gitRoot, configPath)) {
      throw new Error("Invalid config path");
    }

    const content = await fs.readFile(configPath, "utf-8");
    const parsed = YAML.parse(content);

    // Transform snake_case to camelCase and merge with defaults
    return {
      ...DEFAULT_CONFIG,
      enforcementMode: parsed.enforcement_mode || DEFAULT_CONFIG.enforcementMode,
      rulePacks: parsed.rule_packs || DEFAULT_CONFIG.rulePacks,
      security: {
        ...DEFAULT_CONFIG.security,
        blockThreshold: parsed.security?.block_threshold,
        secrets: parsed.security?.secrets,
        sqlInjection: parsed.security?.sql_injection,
      },
      standards: {
        ...DEFAULT_CONFIG.standards,
        naming: parsed.standards?.naming,
        logging: parsed.standards?.logging,
        errorHandling: parsed.standards?.error_handling,
      },
      license: parsed.license || DEFAULT_CONFIG.license,
      copilot: {
        ...DEFAULT_CONFIG.copilot,
        strictMode: parsed.copilot?.strict_mode,
      },
    };
  } catch {
    // Return default config if file doesn't exist
    return DEFAULT_CONFIG;
  }
}

export async function saveConfig(config: GuardrailsConfig): Promise<void> {
  const gitRoot = await getGitRoot();
  // Use normalized path and validate it stays within git root
  const configPath = path.normalize(path.join(gitRoot, ".github", "guardrails.yaml"));

  if (!isPathSafe(gitRoot, configPath)) {
    throw new Error("Invalid config path");
  }

  // Transform camelCase to snake_case for YAML
  const yamlConfig = {
    enforcement_mode: config.enforcementMode,
    rule_packs: config.rulePacks,
    security: config.security
      ? {
          block_threshold: config.security.blockThreshold,
          secrets: config.security.secrets,
          sql_injection: config.security.sqlInjection,
        }
      : undefined,
    standards: config.standards
      ? {
          naming: config.standards.naming,
          logging: config.standards.logging,
          error_handling: config.standards.errorHandling,
        }
      : undefined,
    license: config.license,
    copilot: config.copilot
      ? {
          strict_mode: config.copilot.strictMode,
        }
      : undefined,
  };

  const content = YAML.stringify(yamlConfig);
  await fs.writeFile(configPath, content, "utf-8");
}
