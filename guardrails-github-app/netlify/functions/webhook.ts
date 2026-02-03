import type { Handler, HandlerEvent, HandlerContext } from "@netlify/functions";
import { Octokit } from "@octokit/rest";
import { verify } from "@octokit/webhooks-methods";
import { handlePullRequest } from "../../src/handlers/pull-request.js";
import { handlePush } from "../../src/handlers/push.js";

const GITHUB_APP_ID = process.env.GITHUB_APP_ID || "";
const GITHUB_PRIVATE_KEY = process.env.GITHUB_PRIVATE_KEY?.replace(
  /\\n/g,
  "\n"
) || "";
const GITHUB_WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET || "";

interface WebhookPayload {
  action: string;
  installation?: {
    id: number;
  };
  repository?: {
    owner: {
      login: string;
    };
    name: string;
    full_name: string;
  };
  pull_request?: {
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
  number?: number;
}

async function verifyWebhookSignature(
  payload: string,
  signature: string
): Promise<boolean> {
  if (!GITHUB_WEBHOOK_SECRET) {
    console.warn("No webhook secret configured, skipping verification");
    return true;
  }

  try {
    return await verify(GITHUB_WEBHOOK_SECRET, payload, signature);
  } catch (error) {
    console.error("Signature verification error:", error);
    return false;
  }
}

async function createOctokitForInstallation(
  installationId: number
): Promise<Octokit> {
  const { createAppAuth } = await import("@octokit/auth-app");

  const auth = createAppAuth({
    appId: GITHUB_APP_ID,
    privateKey: GITHUB_PRIVATE_KEY,
    installationId,
  });

  const installationAuth = await auth({ type: "installation" });

  return new Octokit({
    auth: installationAuth.token,
  });
}

export const handler: Handler = async (
  event: HandlerEvent,
  _context: HandlerContext
) => {
  // Only accept POST requests
  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: "Method not allowed" }),
    };
  }

  // Get headers
  const signature = event.headers["x-hub-signature-256"] || "";
  const eventType = event.headers["x-github-event"] || "";
  const deliveryId = event.headers["x-github-delivery"] || "";

  console.log(`Received webhook: ${eventType} (delivery: ${deliveryId})`);

  // Verify webhook signature
  if (!(await verifyWebhookSignature(event.body || "", signature))) {
    console.error("Invalid webhook signature");
    return {
      statusCode: 401,
      body: JSON.stringify({ error: "Invalid signature" }),
    };
  }

  // Parse payload
  let payload: WebhookPayload;
  try {
    payload = JSON.parse(event.body || "{}");
  } catch {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: "Invalid JSON payload" }),
    };
  }

  // Handle different event types
  try {
    switch (eventType) {
      case "pull_request":
        if (!payload.installation?.id) {
          console.error("No installation ID in payload");
          return {
            statusCode: 400,
            body: JSON.stringify({ error: "Missing installation ID" }),
          };
        }

        const octokit = await createOctokitForInstallation(
          payload.installation.id
        );

        await handlePullRequest(octokit, {
          action: payload.action,
          number: payload.number || payload.pull_request?.number || 0,
          pull_request: payload.pull_request!,
          repository: payload.repository!,
          installation: payload.installation,
        });
        break;

      case "push":
        if (!payload.installation?.id) {
          console.error("No installation ID in payload");
          return {
            statusCode: 400,
            body: JSON.stringify({ error: "Missing installation ID" }),
          };
        }

        const pushOctokit = await createOctokitForInstallation(
          payload.installation.id
        );

        await handlePush(pushOctokit, payload as any);
        break;

      case "ping":
        console.log("Received ping event");
        return {
          statusCode: 200,
          body: JSON.stringify({ message: "pong" }),
        };

      default:
        console.log(`Ignoring event type: ${eventType}`);
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ success: true, event: eventType }),
    };
  } catch (error) {
    console.error("Error processing webhook:", error);
    return {
      statusCode: 500,
      body: JSON.stringify({
        error: "Internal server error",
        message: error instanceof Error ? error.message : "Unknown error",
      }),
    };
  }
};
