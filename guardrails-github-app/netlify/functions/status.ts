import type { Handler, HandlerEvent, HandlerContext } from "@netlify/functions";
import { healthCheck } from "../../src/services/backend-client.js";

export const handler: Handler = async (
  event: HandlerEvent,
  _context: HandlerContext
) => {
  if (event.httpMethod !== "GET") {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: "Method not allowed" }),
    };
  }

  const startTime = Date.now();

  // Check backend health
  let backendStatus = "healthy";
  try {
    await healthCheck();
  } catch (error) {
    backendStatus = `unhealthy: ${error instanceof Error ? error.message : "Unknown error"}`;
  }

  const responseTime = Date.now() - startTime;

  const status = {
    status: backendStatus === "healthy" ? "healthy" : "degraded",
    version: process.env.npm_package_version || "1.0.0",
    environment: process.env.NODE_ENV || "development",
    components: {
      webhook: "healthy",
      backend: backendStatus,
    },
    responseTimeMs: responseTime,
    timestamp: new Date().toISOString(),
  };

  return {
    statusCode: status.status === "healthy" ? 200 : 503,
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(status),
  };
};
