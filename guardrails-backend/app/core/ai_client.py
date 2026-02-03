import httpx
import json
from typing import Optional, Any
from pydantic import BaseModel

from app.config import get_settings

settings = get_settings()


class AIResponse(BaseModel):
    content: str
    model: str
    tokens_used: int
    stop_reason: Optional[str] = None


class AIClient:
    """Client for Claude Sonnet 4.5 via Vercel AI Gateway."""

    def __init__(self):
        self.base_url = settings.anthropic_base_url
        self.api_key = settings.vercel_ai_gateway_api_key
        self.model = settings.ai_model
        self.max_tokens = settings.ai_max_tokens

    async def _make_request(
        self,
        messages: list[dict],
        system: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: float = 0.0,
    ) -> AIResponse:
        """Make a request to the Vercel AI Gateway."""
        headers = {
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }

        if self.api_key:
            # Vercel AI Gateway Anthropic-compatible API uses x-api-key header
            headers["x-api-key"] = self.api_key

        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens or self.max_tokens,
            "temperature": temperature,
            "messages": messages,
        }

        if system:
            payload["system"] = system

        url = f"{self.base_url}/v1/messages"
        print(f"[AIClient] Making request to {url} with model {self.model}")

        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                response = await client.post(
                    url,
                    headers=headers,
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
                print(f"[AIClient] Request successful, got response")
            except httpx.HTTPStatusError as e:
                print(f"[AIClient] HTTP error {e.response.status_code}: {e.response.text}")
                raise
            except httpx.TimeoutException as e:
                print(f"[AIClient] Request timed out: {e}")
                raise
            except Exception as e:
                print(f"[AIClient] Request failed: {e}")
                raise

            content = ""
            for block in data.get("content", []):
                if block.get("type") == "text":
                    content += block.get("text", "")

            return AIResponse(
                content=content,
                model=data.get("model", self.model),
                tokens_used=data.get("usage", {}).get("input_tokens", 0)
                + data.get("usage", {}).get("output_tokens", 0),
                stop_reason=data.get("stop_reason"),
            )

    async def analyze_security(
        self,
        code: str,
        file_path: str,
        language: str,
    ) -> dict:
        """Analyze code for security vulnerabilities."""
        system = """You are an expert security code reviewer. Analyze code for security vulnerabilities and provide detailed findings.

For each issue found, provide:
1. severity: critical, high, medium, low, or info
2. title: Brief description of the issue
3. description: Detailed explanation
4. line_start and line_end: Line numbers where the issue occurs
5. owasp_mapping: OWASP Top 10 category if applicable (e.g., "A03:2021 - Injection")
6. cwe_id: CWE ID if applicable (e.g., "CWE-89")
7. explanation: Why this is a security issue
8. suggested_fix: How to fix the issue with code example

Respond in JSON format with a "violations" array."""

        prompt = f"""Analyze this {language} code for security vulnerabilities:

File: {file_path}

```{language}
{code}
```

Check for:
- Hardcoded secrets (API keys, passwords, tokens)
- SQL injection
- Command injection
- Insecure deserialization
- Path traversal
- XSS vulnerabilities
- Authentication/authorization issues
- Sensitive data exposure

Respond with JSON containing a "violations" array. If no issues found, return {{"violations": []}}."""

        response = await self._make_request(
            messages=[{"role": "user", "content": prompt}],
            system=system,
        )

        try:
            # Extract JSON from response
            content = response.content.strip()
            if content.startswith("```json"):
                content = content[7:]
            if content.startswith("```"):
                content = content[3:]
            if content.endswith("```"):
                content = content[:-3]
            result = json.loads(content.strip())
            result["tokens_used"] = response.tokens_used
            result["model"] = response.model
            return result
        except json.JSONDecodeError:
            return {
                "violations": [],
                "error": "Failed to parse AI response",
                "raw_response": response.content,
                "tokens_used": response.tokens_used,
                "model": response.model,
            }

    async def analyze_standards(
        self,
        code: str,
        file_path: str,
        language: str,
        config: Optional[dict] = None,
    ) -> dict:
        """Analyze code against enterprise coding standards."""
        system = """You are an expert code reviewer focused on enterprise coding standards. Analyze code for compliance with best practices.

For each issue found, provide:
1. severity: high, medium, low, or info
2. title: Brief description
3. description: Detailed explanation
4. line_start and line_end: Line numbers
5. category: naming, logging, error_handling, or other
6. explanation: Why this matters
7. suggested_fix: How to fix with code example

Respond in JSON format with a "violations" array."""

        config_str = json.dumps(config) if config else "default enterprise standards"

        prompt = f"""Analyze this {language} code against enterprise coding standards:

File: {file_path}
Configuration: {config_str}

```{language}
{code}
```

Check for:
- Naming convention violations (camelCase for functions, PascalCase for classes, SCREAMING_SNAKE_CASE for constants)
- Missing or inadequate logging
- Improper error handling (empty catch blocks, swallowed exceptions)
- Console.log in production code
- Missing type annotations (for TypeScript)
- Code documentation issues

Respond with JSON containing a "violations" array. If no issues found, return {{"violations": []}}."""

        response = await self._make_request(
            messages=[{"role": "user", "content": prompt}],
            system=system,
        )

        try:
            content = response.content.strip()
            if content.startswith("```json"):
                content = content[7:]
            if content.startswith("```"):
                content = content[3:]
            if content.endswith("```"):
                content = content[:-3]
            result = json.loads(content.strip())
            result["tokens_used"] = response.tokens_used
            result["model"] = response.model
            return result
        except json.JSONDecodeError:
            return {
                "violations": [],
                "error": "Failed to parse AI response",
                "tokens_used": response.tokens_used,
                "model": response.model,
            }

    async def detect_copilot_code(
        self,
        code: str,
        file_path: str,
        language: str,
    ) -> dict:
        """Detect if code appears to be AI-generated."""
        system = """You are an expert at detecting AI-generated code. Analyze code patterns to determine if code was likely generated by GitHub Copilot or similar AI tools.

Look for:
1. Overly generic variable names (data, result, temp, item)
2. Boilerplate patterns without customization
3. Missing edge case handling
4. Lack of project-specific naming or patterns
5. Uniform comment styles typical of AI
6. Perfect but generic implementations

Respond in JSON format."""

        prompt = f"""Analyze this {language} code to determine if it appears AI-generated:

File: {file_path}

```{language}
{code}
```

Provide:
1. is_ai_generated: boolean
2. confidence: 0-100 percentage
3. ai_code_lines: array of line numbers that appear AI-generated
4. indicators: list of reasons for your assessment

Respond with JSON."""

        response = await self._make_request(
            messages=[{"role": "user", "content": prompt}],
            system=system,
        )

        try:
            content = response.content.strip()
            if content.startswith("```json"):
                content = content[7:]
            if content.startswith("```"):
                content = content[3:]
            if content.endswith("```"):
                content = content[:-3]
            result = json.loads(content.strip())
            result["tokens_used"] = response.tokens_used
            result["model"] = response.model
            return result
        except json.JSONDecodeError:
            return {
                "is_ai_generated": False,
                "confidence": 0,
                "ai_code_lines": [],
                "error": "Failed to parse AI response",
                "tokens_used": response.tokens_used,
                "model": response.model,
            }

    async def suggest_fix(
        self,
        code: str,
        violation: dict,
        language: str,
    ) -> dict:
        """Generate a fix suggestion for a violation."""
        system = """You are an expert code fixer. Given a code violation, provide a secure and compliant fix.

Provide:
1. fixed_code: The corrected code
2. diff: A unified diff showing the changes
3. explanation: Why this fix addresses the issue
4. confidence: 0-1 confidence in the fix

Respond in JSON format."""

        prompt = f"""Fix this {language} code violation:

Original code:
```{language}
{code}
```

Violation:
- Title: {violation.get('title', 'Unknown')}
- Description: {violation.get('description', 'No description')}
- Line: {violation.get('line_start', 'Unknown')}

Provide a secure and compliant fix. Respond with JSON containing fixed_code, diff, explanation, and confidence."""

        response = await self._make_request(
            messages=[{"role": "user", "content": prompt}],
            system=system,
        )

        try:
            content = response.content.strip()
            if content.startswith("```json"):
                content = content[7:]
            if content.startswith("```"):
                content = content[3:]
            if content.endswith("```"):
                content = content[:-3]
            result = json.loads(content.strip())
            result["tokens_used"] = response.tokens_used
            result["model"] = response.model
            return result
        except json.JSONDecodeError:
            return {
                "fixed_code": "",
                "diff": "",
                "explanation": "Failed to generate fix",
                "confidence": 0,
                "error": "Failed to parse AI response",
                "tokens_used": response.tokens_used,
                "model": response.model,
            }

    async def map_to_owasp(
        self,
        vulnerability_type: str,
        code_context: str,
    ) -> dict:
        """Map a vulnerability to OWASP Top 10 and CWE."""
        prompt = f"""Map this vulnerability to OWASP Top 10 and CWE:

Vulnerability type: {vulnerability_type}
Code context: {code_context}

Respond with JSON containing:
- owasp: OWASP Top 10 category (e.g., "A03:2021 - Injection")
- cwe: Array of relevant CWE IDs (e.g., ["CWE-89", "CWE-564"])
- description: Brief explanation of the mapping"""

        response = await self._make_request(
            messages=[{"role": "user", "content": prompt}],
        )

        try:
            content = response.content.strip()
            if content.startswith("```json"):
                content = content[7:]
            if content.startswith("```"):
                content = content[3:]
            if content.endswith("```"):
                content = content[:-3]
            return json.loads(content.strip())
        except json.JSONDecodeError:
            return {
                "owasp": None,
                "cwe": [],
                "error": "Failed to map vulnerability",
            }
