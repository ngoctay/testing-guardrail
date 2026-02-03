import { Octokit } from "@octokit/rest";
import type { ScanRequest, ScanResponse } from "../types/index.js";
import { scanCode, getRepoConfig } from "../services/backend-client.js";
import { formatPrComment } from "../services/comment-formatter.js";
import { determineEnforcement } from "../services/enforcement.js";

interface PullRequestPayload {
  action: string;
  number: number;
  pull_request: {
    number: number;
    head: {
      sha: string;
      ref: string;
    };
    base: {
      ref: string;
    };
    user: {
      login: string;
    };
  };
  repository: {
    owner: {
      login: string;
    };
    name: string;
    full_name: string;
  };
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

export async function handlePullRequest(
  octokit: Octokit,
  payload: PullRequestPayload
): Promise<void> {
  const { action, number: prNumber, repository, pull_request: pr } = payload;

  // Only process opened or synchronized events
  if (action !== "opened" && action !== "synchronize") {
    console.log(`Skipping PR event action: ${action}`);
    return;
  }

  const owner = repository.owner.login;
  const repo = repository.name;

  console.log(`Processing PR #${prNumber} in ${owner}/${repo}`);

  try {
    // Get repository configuration
    const config = await getRepoConfig(owner, repo);
    console.log(`[PR Handler] Config: enforcementMode=${config.enforcementMode}, rulePacks=${config.enabledRulePacks?.join(',') ?? 'undefined'}`);

    // Get PR files
    const { data: files } = await octokit.pulls.listFiles({
      owner,
      repo,
      pull_number: prNumber,
      per_page: 100,
    });

    // Filter to supported files
    const supportedFiles = files.filter((file) =>
      SUPPORTED_EXTENSIONS.some((ext) => file.filename.endsWith(ext))
    );

    if (supportedFiles.length === 0) {
      console.log("No supported files found in PR");
      return;
    }

    console.log(`Found ${supportedFiles.length} supported files to scan`);

    // Scan each file
    const allResults: ScanResponse[] = [];

    for (const file of supportedFiles) {
      console.log(`[PR Handler] Processing file: ${file.filename} (status: ${file.status})`);

      if (file.status === "removed") {
        console.log(`[PR Handler] Skipping removed file: ${file.filename}`);
        continue;
      }

      try {
        // Get file content
        const content = await getFileContent(octokit, owner, repo, file, pr.head.sha);
        if (!content) {
          console.log(`[PR Handler] No content retrieved for file: ${file.filename}, skipping`);
          continue;
        }
        console.log(`[PR Handler] Got content for ${file.filename}: ${content.length} chars`);

        const language = getLanguageFromFile(file.filename);

        const scanRequest: ScanRequest = {
          code: content,
          filePath: file.filename,
          language,
          diffOnly: true,
          context: {
            org: owner,
            repo,
            prNumber,
            commitSha: pr.head.sha,
            author: pr.user.login,
          },
          options: {
            enableAi: true,
            enforcementMode: config.enforcementMode,
            rulePacks: config.enabledRulePacks,
            customRules: [],
          },
        };

        const result = await scanCode(scanRequest);
        console.log(`[PR Handler] Scan result for ${file.filename}: ${result.summary.totalIssues} violations`);
        allResults.push(result);
      } catch (error) {
        console.error("[PR Handler] Error scanning file:", file.filename, error);
      }
    }

    // Aggregate results
    const aggregatedResult = aggregateResults(allResults);
    console.log(`[PR Handler] Aggregated results: ${allResults.length} files scanned, ${aggregatedResult.summary.totalIssues} total violations`);
    console.log(`[PR Handler] Violation breakdown: critical=${aggregatedResult.summary.critical}, high=${aggregatedResult.summary.high}, medium=${aggregatedResult.summary.medium}, low=${aggregatedResult.summary.low}`);

    // Determine enforcement
    const enforcement = determineEnforcement(aggregatedResult, config);

    // Post PR comment
    const comment = formatPrComment(aggregatedResult, config.override.enabled);

    // Find existing comment to update
    const { data: comments } = await octokit.issues.listComments({
      owner,
      repo,
      issue_number: prNumber,
    });

    const existingComment = comments.find(
      (c) =>
        c.user?.type === "Bot" &&
        c.body?.includes("Guardrails Security & Compliance Report")
    );

    if (existingComment) {
      await octokit.issues.updateComment({
        owner,
        repo,
        comment_id: existingComment.id,
        body: comment,
      });
      console.log(`Updated existing comment ${existingComment.id}`);
    } else {
      await octokit.issues.createComment({
        owner,
        repo,
        issue_number: prNumber,
        body: comment,
      });
      console.log("Created new PR comment");
    }

    // Set commit status
    const statusState = enforcement.shouldBlockMerge ? "failure" : "success";
    const statusDescription = enforcement.reason || "All checks passed";

    await octokit.repos.createCommitStatus({
      owner,
      repo,
      sha: pr.head.sha,
      state: statusState,
      context: "guardrails/security",
      description: statusDescription.substring(0, 140),
      target_url: `https://github.com/${owner}/${repo}/pull/${prNumber}#issuecomment-guardrails`,
    });

    console.log(`Set commit status: ${statusState}`);
  } catch (error) {
    console.error("Error processing PR:", error);
    throw error;
  }
}

async function getFileContent(
  octokit: Octokit,
  owner: string,
  repo: string,
  file: { filename: string },
  sha: string
): Promise<string | null> {
  try {
    console.log(`[getFileContent] Fetching: ${owner}/${repo}/${file.filename}@${sha}`);
    const { data } = await octokit.repos.getContent({
      owner,
      repo,
      path: file.filename,
      ref: sha,
    });

    if ("content" in data && data.content) {
      const content = Buffer.from(data.content, "base64").toString("utf-8");
      console.log(`[getFileContent] Success: ${file.filename} (${content.length} chars)`);
      return content;
    }
    console.log(`[getFileContent] No content field in response for: ${file.filename}`);
    return null;
  } catch (error) {
    console.error("[getFileContent] Error fetching file:", file.filename, error);
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
      scanId: "aggregate",
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

    // Use strongest enforcement action
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
