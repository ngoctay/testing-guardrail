import { describe, it, expect } from "vitest";
import { formatResults, formatResultsJson } from "../services/formatter.js";
import type { ScanResult, Violation } from "../services/api-client.js";

describe("Formatter Service", () => {
  const createViolation = (
    overrides: Partial<Violation> = {}
  ): Violation => ({
    id: "test-id-1",
    ruleId: "SEC-001",
    severity: "high",
    category: "security",
    title: "Test Violation",
    description: "This is a test violation",
    filePath: "test.ts",
    lineStart: 10,
    lineEnd: 10,
    codeSnippet: "const secret = 'password123';",
    explanation: "Hardcoded secrets are dangerous",
    suggestedFix: "Use environment variables instead",
    ...overrides,
  });

  const createScanResult = (
    violations: Violation[] = [],
    overrides: Partial<ScanResult> = {}
  ): ScanResult => ({
    scanId: "scan-123",
    status: violations.length > 0 ? "violations_found" : "clean",
    summary: {
      totalIssues: violations.length,
      critical: violations.filter((v) => v.severity === "critical").length,
      high: violations.filter((v) => v.severity === "high").length,
      medium: violations.filter((v) => v.severity === "medium").length,
      low: violations.filter((v) => v.severity === "low").length,
      info: violations.filter((v) => v.severity === "info").length,
    },
    violations,
    enforcementAction: "none",
    ...overrides,
  });

  describe("formatResults", () => {
    it("should return empty string for clean results", () => {
      const result = createScanResult([]);
      const output = formatResults([result], false);
      expect(output).toBe("");
    });

    it("should format a single violation", () => {
      const violation = createViolation();
      const result = createScanResult([violation]);
      const output = formatResults([result], false);

      expect(output).toContain("HIGH");
      expect(output).toContain("Test Violation");
      expect(output).toContain("test.ts:10");
      expect(output).toContain("SEC-001");
    });

    it("should include OWASP mapping when present", () => {
      const violation = createViolation({ owaspMapping: "A07:2021" });
      const result = createScanResult([violation]);
      const output = formatResults([result], false);

      expect(output).toContain("OWASP: A07:2021");
    });

    it("should include CWE ID when present", () => {
      const violation = createViolation({ cweId: "CWE-798" });
      const result = createScanResult([violation]);
      const output = formatResults([result], false);

      expect(output).toContain("CWE: CWE-798");
    });

    it("should include code snippet", () => {
      const violation = createViolation({
        codeSnippet: "const api_key = 'sk_live_123';",
      });
      const result = createScanResult([violation]);
      const output = formatResults([result], false);

      expect(output).toContain("const api_key = 'sk_live_123';");
    });

    it("should include suggested fix", () => {
      const violation = createViolation({
        suggestedFix: "Use process.env.API_KEY instead",
      });
      const result = createScanResult([violation]);
      const output = formatResults([result], false);

      expect(output).toContain("Suggested fix:");
      expect(output).toContain("Use process.env.API_KEY instead");
    });

    it("should show description in verbose mode", () => {
      const violation = createViolation({
        description: "This is a detailed description",
      });
      const result = createScanResult([violation]);
      const output = formatResults([result], true);

      expect(output).toContain("This is a detailed description");
    });

    it("should show explanation in verbose mode", () => {
      const violation = createViolation({
        explanation: "Detailed explanation here",
      });
      const result = createScanResult([violation]);
      const output = formatResults([result], true);

      expect(output).toContain("Why:");
      expect(output).toContain("Detailed explanation here");
    });

    it("should format multiple violations", () => {
      const violations = [
        createViolation({ id: "1", title: "First Issue", severity: "critical" }),
        createViolation({ id: "2", title: "Second Issue", severity: "high" }),
        createViolation({ id: "3", title: "Third Issue", severity: "medium" }),
      ];
      const result = createScanResult(violations);
      const output = formatResults([result], false);

      expect(output).toContain("First Issue");
      expect(output).toContain("Second Issue");
      expect(output).toContain("Third Issue");
    });

    it("should order violations by severity", () => {
      const violations = [
        createViolation({ id: "1", title: "Low Issue", severity: "low" }),
        createViolation({ id: "2", title: "Critical Issue", severity: "critical" }),
        createViolation({ id: "3", title: "High Issue", severity: "high" }),
      ];
      const result = createScanResult(violations);
      const output = formatResults([result], false);

      // Critical should appear before high, which should appear before low
      const criticalIndex = output.indexOf("Critical Issue");
      const highIndex = output.indexOf("High Issue");
      const lowIndex = output.indexOf("Low Issue");

      expect(criticalIndex).toBeLessThan(highIndex);
      expect(highIndex).toBeLessThan(lowIndex);
    });
  });

  describe("formatResultsJson", () => {
    it("should return valid JSON", () => {
      const result = createScanResult([]);
      const output = formatResultsJson([result]);
      const parsed = JSON.parse(output);

      expect(parsed).toBeDefined();
      expect(parsed.summary).toBeDefined();
      expect(parsed.results).toBeDefined();
    });

    it("should include summary with correct counts", () => {
      const violations = [
        createViolation({ severity: "critical" }),
        createViolation({ severity: "high" }),
        createViolation({ severity: "high" }),
        createViolation({ severity: "medium" }),
      ];
      const result = createScanResult(violations);
      const output = formatResultsJson([result]);
      const parsed = JSON.parse(output);

      expect(parsed.summary.totalIssues).toBe(4);
      expect(parsed.summary.critical).toBe(1);
      expect(parsed.summary.high).toBe(2);
      expect(parsed.summary.medium).toBe(1);
    });

    it("should include all results", () => {
      const result1 = createScanResult([createViolation()]);
      const result2 = createScanResult([createViolation()]);
      const output = formatResultsJson([result1, result2]);
      const parsed = JSON.parse(output);

      expect(parsed.results).toHaveLength(2);
    });

    it("should aggregate summary across multiple results", () => {
      const result1 = createScanResult([
        createViolation({ severity: "critical" }),
      ]);
      const result2 = createScanResult([
        createViolation({ severity: "high" }),
        createViolation({ severity: "high" }),
      ]);
      const output = formatResultsJson([result1, result2]);
      const parsed = JSON.parse(output);

      expect(parsed.summary.totalIssues).toBe(3);
      expect(parsed.summary.critical).toBe(1);
      expect(parsed.summary.high).toBe(2);
    });
  });
});
