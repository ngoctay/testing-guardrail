import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

describe("API Client", () => {
  const originalFetch = global.fetch;
  const mockFetch = vi.fn();

  beforeEach(() => {
    global.fetch = mockFetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
    vi.clearAllMocks();
  });

  describe("ScanRequest interface", () => {
    it("should have correct shape", async () => {
      const { scanCode } = await import("../services/api-client.js");

      const mockResponse = {
        scan_id: "test-123",
        status: "clean",
        summary: {
          total_issues: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
        },
        violations: [],
        enforcement_action: "none",
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const request = {
        code: "const x = 1;",
        filePath: "test.ts",
        language: "typescript",
        enableAi: false,
        enforcementMode: "warning",
        rulePacks: ["default-security"],
      };

      const result = await scanCode(request);

      expect(result.scanId).toBe("test-123");
      expect(result.status).toBe("clean");
    });
  });

  describe("scanCode", () => {
    it("should transform response from snake_case to camelCase", async () => {
      const { scanCode } = await import("../services/api-client.js");

      const mockResponse = {
        scan_id: "scan-123",
        status: "violations_found",
        summary: {
          total_issues: 1,
          critical: 0,
          high: 1,
          medium: 0,
          low: 0,
          info: 0,
        },
        violations: [
          {
            id: "v-1",
            rule_id: "SEC-001",
            severity: "high",
            category: "security",
            title: "Hardcoded Secret",
            description: "Found hardcoded secret",
            file_path: "test.ts",
            line_start: 1,
            line_end: 1,
            code_snippet: "const secret = 'abc';",
            owasp_mapping: "A07:2021",
            cwe_id: "CWE-798",
            explanation: "Secrets should not be hardcoded",
            suggested_fix: "Use environment variables",
          },
        ],
        enforcement_action: "annotate",
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const request = {
        code: "const secret = 'abc';",
        filePath: "test.ts",
        language: "typescript",
        enableAi: false,
        enforcementMode: "warning",
        rulePacks: ["default-security"],
      };

      const result = await scanCode(request);

      // Check camelCase transformation
      expect(result.scanId).toBe("scan-123");
      expect(result.summary.totalIssues).toBe(1);
      expect(result.violations[0].ruleId).toBe("SEC-001");
      expect(result.violations[0].filePath).toBe("test.ts");
      expect(result.violations[0].lineStart).toBe(1);
      expect(result.violations[0].lineEnd).toBe(1);
      expect(result.violations[0].codeSnippet).toBe("const secret = 'abc';");
      expect(result.violations[0].owaspMapping).toBe("A07:2021");
      expect(result.violations[0].cweId).toBe("CWE-798");
      expect(result.violations[0].suggestedFix).toBe("Use environment variables");
      expect(result.enforcementAction).toBe("annotate");
    });

    it("should return local result when API is unavailable", async () => {
      const { scanCode } = await import("../services/api-client.js");

      mockFetch.mockRejectedValueOnce(new Error("Network error"));

      const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

      const request = {
        code: "const x = 1;",
        filePath: "test.ts",
        language: "typescript",
        enableAi: false,
        enforcementMode: "warning",
        rulePacks: ["default-security"],
      };

      const result = await scanCode(request);

      expect(result.scanId).toBe("local");
      expect(result.status).toBe("clean");
      expect(result.violations).toHaveLength(0);
      expect(consoleSpy).toHaveBeenCalled();

      consoleSpy.mockRestore();
    });

    it("should return local result when API returns non-OK status", async () => {
      const { scanCode } = await import("../services/api-client.js");

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
      });

      const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

      const request = {
        code: "const x = 1;",
        filePath: "test.ts",
        language: "typescript",
        enableAi: false,
        enforcementMode: "warning",
        rulePacks: ["default-security"],
      };

      const result = await scanCode(request);

      expect(result.scanId).toBe("local");
      expect(result.status).toBe("clean");

      consoleSpy.mockRestore();
    });

    it("should send correct request body to API", async () => {
      const { scanCode } = await import("../services/api-client.js");

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          scan_id: "test",
          status: "clean",
          summary: { total_issues: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          violations: [],
          enforcement_action: "none",
        }),
      });

      await scanCode({
        code: "const x = 1;",
        filePath: "src/test.ts",
        language: "typescript",
        enableAi: true,
        enforcementMode: "blocking",
        rulePacks: ["default-security", "healthcare"],
      });

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url, options] = mockFetch.mock.calls[0];

      expect(url).toContain("/api/v1/scan");
      expect(options.method).toBe("POST");
      expect(options.headers["Content-Type"]).toBe("application/json");

      const body = JSON.parse(options.body);
      expect(body.code).toBe("const x = 1;");
      expect(body.file_path).toBe("src/test.ts");
      expect(body.language).toBe("typescript");
      expect(body.options.enable_ai).toBe(true);
      expect(body.options.enforcement_mode).toBe("blocking");
      expect(body.options.rule_packs).toEqual(["default-security", "healthcare"]);
    });
  });

  describe("Violation interface", () => {
    it("should support all severity levels", async () => {
      const { scanCode } = await import("../services/api-client.js");

      const severities = ["critical", "high", "medium", "low", "info"];

      for (const severity of severities) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            scan_id: "test",
            status: "violations_found",
            summary: { total_issues: 1, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            violations: [
              {
                id: "1",
                rule_id: "TEST-001",
                severity,
                category: "security",
                title: "Test",
                description: "Test",
                file_path: "test.ts",
                line_start: 1,
                line_end: 1,
                code_snippet: "",
                explanation: "",
              },
            ],
            enforcement_action: "none",
          }),
        });

        const result = await scanCode({
          code: "",
          filePath: "",
          language: "",
          enableAi: false,
          enforcementMode: "",
          rulePacks: [],
        });

        expect(result.violations[0].severity).toBe(severity);
      }
    });

    it("should support all categories", async () => {
      const { scanCode } = await import("../services/api-client.js");

      const categories = ["security", "standards", "license"];

      for (const category of categories) {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            scan_id: "test",
            status: "violations_found",
            summary: { total_issues: 1, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            violations: [
              {
                id: "1",
                rule_id: "TEST-001",
                severity: "medium",
                category,
                title: "Test",
                description: "Test",
                file_path: "test.ts",
                line_start: 1,
                line_end: 1,
                code_snippet: "",
                explanation: "",
              },
            ],
            enforcement_action: "none",
          }),
        });

        const result = await scanCode({
          code: "",
          filePath: "",
          language: "",
          enableAi: false,
          enforcementMode: "",
          rulePacks: [],
        });

        expect(result.violations[0].category).toBe(category);
      }
    });
  });
});
