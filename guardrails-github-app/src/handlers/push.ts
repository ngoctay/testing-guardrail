import { Octokit } from "@octokit/rest";
import type { ScanRequest, ScanResponse } from "../types/index.js";
import { scanCode, getRepoConfig } from "../services/backend-client.js";

interface PushPayload {
  ref: string;
  before: string;
  after: string;
  repository: {
    owner: {
      login: string;
      name?: string;
    };
    name: string;
    full_name: string;
  };
  pusher: {
    name: string;
    email?: string;
  };
  commits: Array<{
    id: string;
    message: string;
    author: {
      name: string;
      email: string;
    };
    added: string[];
    modified: string[];
    removed: string[];
  }>;
  installation?: {
    id: number;
  };
}

const SUPPORTED_EXTENSIONS = [
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".py",
  ".java",
  ".go",
  ".rb",
  ".rs",
  ".cpp",
  ".c",
  ".cs",
  ".php",
  ".swift",
  ".kt",
];

export async function handlePush(
  octokit: Octokit,
  payload: PushPayload
): Promise<void> {
  const { ref, repository, commits, after } = payload;

  // Only process pushes to main/master branches for now
  const branch = ref.replace("refs/heads/", "");
  if (branch !== "main" && branch !== "master") {
    console.log(`Skipping push to non-main branch: ${branch}`);
    return;
  }

  const owner = repository.owner.login || repository.owner.name || "";
  const repo = repository.name;

  console.log(`Processing push to ${branch} in ${owner}/${repo}`);
  console.log(`Commits: ${commits.length}`);

  if (commits.length === 0) {
    console.log("No commits to process");
    return;
  }

  try {
    // Get repository configuration
    const config = await getRepoConfig(owner, repo);
    console.log(`Config: enforcement_mode=${config.enforcementMode}`);

    // Collect all changed files from commits
    const changedFiles = new Set<string>();
    for (const commit of commits) {
      commit.added.forEach((f) => changedFiles.add(f));
      commit.modified.forEach((f) => changedFiles.add(f));
    }

    // Filter to supported files
    const supportedFiles = Array.from(changedFiles).filter((file) =>
      SUPPORTED_EXTENSIONS.some((ext) => file.endsWith(ext))
    );

    if (supportedFiles.length === 0) {
      console.log("No supported files found in push");
      return;
    }

    console.log(`Found ${supportedFiles.length} supported files to scan`);

    // Scan each file
    const allResults: ScanResponse[] = [];

    for (const filePath of supportedFiles) {
      try {
        // Get file content at the commit
        const content = await getFileContent(octokit, owner, repo, filePath, after);
        if (!content) {
          continue;
        }

        const language = getLanguageFromFile(filePath);

        const scanRequest: ScanRequest = {
          code: content,
          filePath,
          language,
          diffOnly: false,
          context: {
            org: owner,
            repo,
            commitSha: after,
            author: payload.pusher.name,
            branch,
          },
          options: {
            enableAi: true,
            enforcementMode: config.enforcementMode,
            rulePacks: config.enabledRulePacks,
            customRules: [],
          },
        };

        const result = await scanCode(scanRequest);
        allResults.push(result);
      } catch (error) {
        console.error("Error scanning file:", filePath, error);
      }
    }

    // Aggregate results
    const aggregatedResult = aggregateResults(allResults);

    // Set commit status based on results
    const hasCriticalIssues = aggregatedResult.summary.critical > 0;
    const hasHighIssues = aggregatedResult.summary.high > 0;

    let statusState: "success" | "failure" | "pending" = "success";
    let statusDescription = "All security checks passed";

    if (config.enforcementMode === "blocking" && (hasCriticalIssues || hasHighIssues)) {
      statusState = "failure";
      statusDescription = `Found ${aggregatedResult.summary.critical} critical and ${aggregatedResult.summary.high} high severity issues`;
    } else if (aggregatedResult.summary.totalIssues > 0) {
      statusDescription = `Found ${aggregatedResult.summary.totalIssues} issues (${aggregatedResult.summary.critical} critical, ${aggregatedResult.summary.high} high)`;
    }

    await octokit.repos.createCommitStatus({
      owner,
      repo,
      sha: after,
      state: statusState,
      context: "guardrails/security",
      description: statusDescription.substring(0, 140),
    });

    console.log(`Set commit status: ${statusState} - ${statusDescription}`);

    // Log summary
    console.log(`Push scan complete for ${owner}/${repo}@${after.substring(0, 7)}`);
    console.log(`Total issues: ${aggregatedResult.summary.totalIssues}`);
    console.log(`Critical: ${aggregatedResult.summary.critical}, High: ${aggregatedResult.summary.high}`);
  } catch (error) {
    console.error("Error processing push:", error);
    throw error;
  }
}

async function getFileContent(
  octokit: Octokit,
  owner: string,
  repo: string,
  path: string,
  ref: string
): Promise<string | null> {
  try {
    const { data } = await octokit.repos.getContent({
      owner,
      repo,
      path,
      ref,
    });

    if ("content" in data && data.content) {
      return Buffer.from(data.content, "base64").toString("utf-8");
    }
    return null;
  } catch {
    console.log(`Could not get content for ${path}`);
    return null;
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
    swift: "swift",
    kt: "kotlin",
  };
  return langMap[ext] || ext;
}

function aggregateResults(results: ScanResponse[]): ScanResponse {
  if (results.length === 0) {
    return {
      scanId: "push-aggregate",
      status: "clean",
      summary: {
        totalIssues: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      },
      violations: [],
      copilotAnalysis: {
        detectedAiCode: false,
        aiCodePercentage: 0,
        aiCodeLines: [],
      },
      enforcementAction: "none",
      createdAt: new Date().toISOString(),
    };
  }

  const aggregated: ScanResponse = {
    scanId: results[0].scanId,
    status: "clean",
    summary: {
      totalIssues: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    },
    violations: [],
    copilotAnalysis: {
      detectedAiCode: false,
      aiCodePercentage: 0,
      aiCodeLines: [],
    },
    enforcementAction: "none",
    createdAt: new Date().toISOString(),
  };

  for (const result of results) {
    aggregated.summary.totalIssues += result.summary.totalIssues;
    aggregated.summary.critical += result.summary.critical;
    aggregated.summary.high += result.summary.high;
    aggregated.summary.medium += result.summary.medium;
    aggregated.summary.low += result.summary.low;
    aggregated.summary.info += result.summary.info;
    aggregated.violations.push(...result.violations);

    if (result.copilotAnalysis.detectedAiCode) {
      aggregated.copilotAnalysis.detectedAiCode = true;
    }

    if (result.enforcementAction === "block") {
      aggregated.enforcementAction = "block";
    } else if (
      result.enforcementAction === "annotate" &&
      aggregated.enforcementAction !== "block"
    ) {
      aggregated.enforcementAction = "annotate";
    }
  }

  if (aggregated.summary.totalIssues > 0) {
    aggregated.status = "violations_found";
  }

  return aggregated;
}
